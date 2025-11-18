import { Request, Response } from 'express';
import { supabaseAdmin } from '../lib/supabase';
import { gerarDeviceToken, hashDeviceToken } from '../utils/deviceToken';
import bcrypt from 'bcrypt';

interface ReqWithUser extends Request {
  usuarioId?: string;
}

/**
 * POST /device/register
 */
export async function registrarDispositivo(req: Request, res: Response) {
  try {
    const { codigo_esp, nome } = req.body;
    if (!codigo_esp) return res.status(400).json({ erro: 'codigo_esp é obrigatório' });

    // procura dispositivo existente
    const { data: existing, error: exErr } = await supabaseAdmin
      .from('dispositivos')
      .select('*')
      .eq('codigo_esp', codigo_esp)
      .limit(1)
      .maybeSingle();

    if (exErr) {
      return res.status(500).json({ erro: 'Erro ao verificar dispositivo', detalhe: exErr.message });
    }

    const tokenPlain = gerarDeviceToken();
    const tokenHash = await hashDeviceToken(tokenPlain);

    if (!existing) {
      // cria novo dispositivo (assistido_id fica null)
      const { data: created, error: createErr } = await supabaseAdmin
        .from('dispositivos')
        .insert({
          nome: nome || null,
          codigo_esp,
          segredo_hash: null,
          device_token_hash: tokenHash,
          token_revoked: false
        })
        .select('*')
        .single();

      if (createErr) {
        return res.status(500).json({ erro: 'Falha ao criar dispositivo', detalhe: createErr.message });
      }

      return res.status(201).json({
        device_id: created.id,
        device_token: tokenPlain,
        codigo_esp: created.codigo_esp
      });
    }

    // Se já existe, reemitir token (atualiza hash)
    const { data: upd, error: updErr } = await supabaseAdmin
      .from('dispositivos')
      .update({
        nome: nome || existing.nome,
        device_token_hash: tokenHash,
        token_revoked: false
      })
      .eq('id', existing.id)
      .select('*')
      .single();

    if (updErr) {
      return res.status(500).json({ erro: 'Falha ao atualizar dispositivo', detalhe: updErr.message });
    }

    return res.status(200).json({
      device_id: upd.id,
      device_token: tokenPlain,
      codigo_esp: upd.codigo_esp
    });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno ao registrar dispositivo', detalhe: e?.message });
  }
}

/**
 * POST /device/pair
 * Body: { codigo_esp, assistido_id, pair_code? }
 * Requires user auth (req.usuarioId)
 *
 * Improvement: update only if assistido_id is null to avoid race condition.
 */
export async function parearDispositivo(req: ReqWithUser, res: Response) {
  try {
    const usuarioId = (req as any).usuarioId as string | undefined;
    if (!usuarioId) return res.status(401).json({ erro: 'Não autenticado' });

    const { codigo_esp, assistido_id, pair_code } = req.body;
    if (!codigo_esp || !assistido_id) {
      return res.status(400).json({ erro: 'codigo_esp e assistido_id são obrigatórios' });
    }

    // Verificar que o usuário pertence ao assistido (tem vínculo)
    const { data: vinculo, error: vincErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select('id')
      .eq('usuario_id', usuarioId)
      .eq('assistido_id', assistido_id)
      .limit(1)
      .maybeSingle();

    if (vincErr) {
      return res.status(500).json({ erro: 'Falha ao verificar vínculo', detalhe: vincErr.message });
    }
    if (!vinculo) {
      return res.status(403).json({ erro: 'Você não está vinculado a esse assistido' });
    }

    // Buscar dispositivo
    const { data: dispositivo, error: dispErr } = await supabaseAdmin
      .from('dispositivos')
      .select('*')
      .eq('codigo_esp', codigo_esp)
      .limit(1)
      .maybeSingle();

    if (dispErr) {
      return res.status(500).json({ erro: 'Erro ao buscar dispositivo', detalhe: dispErr.message });
    }
    if (!dispositivo) {
      return res.status(404).json({ erro: 'Dispositivo não encontrado' });
    }

    // Se dispositivo já está pareado com outro assistido -> bloqueia
    if (dispositivo.assistido_id) {
      return res.status(409).json({ erro: 'Dispositivo já está pareado' });
    }

    // Optional: verifica pair_code se implementação suportar (here: skip unless implemented)
    if (dispositivo.pair_code_hash) {
      if (!pair_code) return res.status(400).json({ erro: 'pair_code é obrigatório para este dispositivo' });
      const ok = await bcrypt.compare(pair_code, dispositivo.pair_code_hash);
      if (!ok || dispositivo.pair_code_used || (dispositivo.pair_code_expires_at && new Date(dispositivo.pair_code_expires_at) < new Date())) {
        return res.status(403).json({ erro: 'Pair code inválido ou expirado' });
      }
    }

    // Realiza update condicional: apenas se assistido_id ainda é null (evita race)
    const { data: updated, error: updErr } = await supabaseAdmin
      .from('dispositivos')
      .update({
        assistido_id,
        paired_by: usuarioId,
        paired_at: new Date().toISOString()
      })
      .eq('codigo_esp', codigo_esp)
      .eq('assistido_id', null) // CONDICIONAL IMPORTANTISSIMA
      .select('*')
      .single();

    if (updErr) {
      // se nenhum registro foi atualizado por conta da condição, retornar conflito
      // Supabase retorna error se não foi atualizado; tratamos como conflito
      return res.status(409).json({ erro: 'Falha ao parear: dispositivo pode ter sido pareado por outro usuário' , detalhe: updErr.message});
    }

    // Se usava pair_code, marcar como usado
    if (dispositivo.pair_code_hash) {
      await supabaseAdmin
        .from('dispositivos')
        .update({ pair_code_used: true })
        .eq('id', updated.id);
    }

    return res.json({ mensagem: 'Pareado com sucesso', dispositivo: updated });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno no pareamento', detalhe: e?.message });
  }
}

/**
 * POST /device/event
 * Body: { event_id?, source_timestamp?, event_type?, eixo_x, eixo_y, eixo_z, totalacc, raw_payload? }
 * Auth: deviceAuth middleware
 */
export async function registrarEventoDispositivo(req: Request, res: Response) {
  try {
    // deviceAuth middleware must populate req.device
    const device = (req as any).device;
    if (!device) return res.status(401).json({ erro: 'Dispositivo não autenticado' });

    const {
      event_id = null,
      source_timestamp = null,
      event_type = 'queda',
      eixo_x = null,
      eixo_y = null,
      eixo_z = null,
      totalacc = null,
      raw_payload = null
    } = req.body as any;

    // deduplicação por event_id (se fornecido)
    if (event_id) {
      const { data: exists, error: exErr } = await supabaseAdmin
        .from('hist_quedas')
        .select('id')
        .eq('event_id', event_id)
        .limit(1)
        .maybeSingle();

      if (exErr) {
        return res.status(500).json({ erro: 'Erro ao checar event_id', detalhe: exErr.message });
      }
      if (exists) {
        return res.status(200).json({ ok: true, mensagem: 'Evento já registrado' });
      }
    }

    // Inserir na tabela hist_quedas
    const { data: inserted, error: insErr } = await supabaseAdmin
      .from('hist_quedas')
      .insert({
        event_id,
        source_timestamp: source_timestamp ? source_timestamp : null,
        event_type,
        eixo_x,
        eixo_y,
        eixo_z,
        totalacc,
        raw_payload: raw_payload ? raw_payload : null,
        dispositivo_id: device.id,
        assistido_id: device.assistido_id
      })
      .select('*')
      .single();

    if (insErr) {
      return res.status(500).json({ erro: 'Falha ao registrar evento', detalhe: insErr.message });
    }

    // Atualizar last_seen
    await supabaseAdmin
      .from('dispositivos')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', device.id);

    // Buscar cuidadores vinculados ao assistido - prepare para notificações
    if (device.assistido_id) {
      const { data: cuidadores, error: cErr } = await supabaseAdmin
        .from('usuarios_assistidos')
        .select(`
          usuario:usuarios (
            id,
            nome_completo,
            telefone
          )
        `)
        .eq('assistido_id', device.assistido_id);

      if (!cErr && Array.isArray(cuidadores) && cuidadores.length > 0) {
        for (const c of cuidadores) {
          const usuario = Array.isArray(c.usuario) ? c.usuario[0] : c.usuario;
          if (usuario) {
            // aqui você pode enfileirar notificação (push/SMS) em uma fila/serviço
            console.log(`Notificar ${usuario.id} (${usuario.nome_completo}) sobre queda do assistido ${device.assistido_id}`);
          }
        }
      }
    }

    return res.status(201).json({ ok: true, evento: inserted });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno ao registrar evento', detalhe: e?.message });
  }
}

/**
 * POST /device/heartbeat
 */
export async function heartbeatDispositivo(req: Request, res: Response) {
  try {
    const device = (req as any).device;
    if (!device) return res.status(401).json({ erro: 'Dispositivo não autenticado' });

    const { error: updErr } = await supabaseAdmin
      .from('dispositivos')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', device.id);

    if (updErr) {
      return res.status(500).json({ erro: 'Falha ao atualizar last_seen', detalhe: updErr.message });
    }

    return res.json({ ok: true });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno heartbeat', detalhe: e?.message });
  }
}

/**
 * GET /device/status
 * Auth: deviceAuth
 */
export async function deviceStatus(req: Request, res: Response) {
  try {
    const device = (req as any).device;
    if (!device) return res.status(401).json({ erro: 'Dispositivo não autenticado' });

    const { data: devFresh, error: devErr } = await supabaseAdmin
      .from('dispositivos')
      .select(`
        id,
        codigo_esp,
        assistido_id,
        paired_at,
        last_seen,
        nome,
        firmware_version
      `)
      .eq('id', device.id)
      .limit(1)
      .maybeSingle();

    if (devErr) {
      return res.status(500).json({ erro: 'Erro ao buscar status do dispositivo', detalhe: devErr.message });
    }
    if (!devFresh) {
      return res.status(404).json({ erro: 'Dispositivo não encontrado' });
    }

    const pareado = !!devFresh.assistido_id;

    return res.json({
      pareado,
      assistido_id: devFresh.assistido_id || null,
      codigo_esp: devFresh.codigo_esp,
      paired_at: devFresh.paired_at || null,
      last_seen: devFresh.last_seen || null,
      nome: devFresh.nome || null,
      firmware_version: devFresh.firmware_version || null
    });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno device status', detalhe: e?.message });
  }
}

/**
 * POST /device/unpair
 * Body: { codigo_esp }
 * Auth: requireSupabaseUser
 */
export async function unpairDevice(req: ReqWithUser, res: Response) {
  try {
    const usuarioId = (req as any).usuarioId as string | undefined;
    if (!usuarioId) return res.status(401).json({ erro: 'Não autenticado' });

    const { codigo_esp } = req.body;
    if (!codigo_esp) return res.status(400).json({ erro: 'codigo_esp é obrigatório' });

    // buscar dispositivo
    const { data: dispositivo, error: dErr } = await supabaseAdmin
      .from('dispositivos')
      .select('*')
      .eq('codigo_esp', codigo_esp)
      .limit(1)
      .maybeSingle();

    if (dErr) return res.status(500).json({ erro: 'Erro ao buscar dispositivo', detalhe: dErr.message });
    if (!dispositivo) return res.status(404).json({ erro: 'Dispositivo não encontrado' });

    if (!dispositivo.assistido_id) {
      return res.status(400).json({ erro: 'Dispositivo não está pareado' });
    }

    // verificar se o usuário tem vínculo com esse assistido (somente vinculado pode desvincular)
    const { data: vinculo, error: vincErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select('id')
      .eq('usuario_id', usuarioId)
      .eq('assistido_id', dispositivo.assistido_id)
      .limit(1)
      .maybeSingle();

    if (vincErr) return res.status(500).json({ erro: 'Erro ao verificar vínculo', detalhe: vincErr.message });
    if (!vinculo) return res.status(403).json({ erro: 'Você não tem permissão para desvincular este dispositivo' });

    // desvincular
    const { data: updated, error: updErr } = await supabaseAdmin
      .from('dispositivos')
      .update({
        assistido_id: null,
        paired_by: null,
        paired_at: null
      })
      .eq('id', dispositivo.id)
      .select('*')
      .single();

    if (updErr) return res.status(500).json({ erro: 'Falha ao desvincular dispositivo', detalhe: updErr.message });

    return res.json({ mensagem: 'Dispositivo desvinculado com sucesso', dispositivo: updated });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno unpair', detalhe: e?.message });
  }
}

/**
 * GET /assistidos/:id/quedas
 * Auth: requireSupabaseUser
 */
export async function listarQuedasAssistido(req: ReqWithUser, res: Response) {
  try {
    const usuarioId = (req as any).usuarioId as string | undefined;
    if (!usuarioId) return res.status(401).json({ erro: 'Não autenticado' });

    const assistidoId = req.params.id;
    if (!assistidoId) return res.status(400).json({ erro: 'assistido id requerido' });

    // verificar vínculo
    const { data: vinculo, error: vincErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select('id')
      .eq('usuario_id', usuarioId)
      .eq('assistido_id', assistidoId)
      .limit(1)
      .maybeSingle();

    if (vincErr) return res.status(500).json({ erro: 'Erro ao verificar vínculo', detalhe: vincErr.message });
    if (!vinculo) return res.status(403).json({ erro: 'Você não está vinculado a esse assistido' });

    // buscar quedas (paginável)
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize as string) || 20, 100);
    const offset = (page - 1) * pageSize;

    const { data: quedas, error: qErr } = await supabaseAdmin
      .from('hist_quedas')
      .select(`
        id,
        created_at,
        event_id,
        source_timestamp,
        event_type,
        eixo_x,
        eixo_y,
        eixo_z,
        totalacc,
        raw_payload,
        dispositivo_id
      `)
      .eq('assistido_id', assistidoId)
      .order('created_at', { ascending: false })
      .range(offset, offset + pageSize - 1);

    if (qErr) return res.status(500).json({ erro: 'Erro ao listar quedas', detalhe: qErr.message });

    return res.json({ page, pageSize, items: quedas || [] });
  } catch (e: any) {
    return res.status(500).json({ erro: 'Erro interno listar quedas', detalhe: e?.message });
  }
}
