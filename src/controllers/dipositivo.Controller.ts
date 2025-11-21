import { Request, Response } from 'express';
import { supabaseAdmin } from '../lib/supabase';
import {
  gerarDeviceToken,
  hashDeviceToken,
  gerarCodigoCurto
} from '../utils/deviceToken';
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

    if (!codigo_esp) {
      return res.status(400).json({ erro: 'codigo_esp é obrigatório' });
    }

    // Buscar se já existe
    const { data: existing, error: exErr } = await supabaseAdmin
      .from('dispositivos')
      .select('*')
      .eq('codigo_esp', codigo_esp)
      .limit(1)
      .maybeSingle();

    if (exErr) {
      return res.status(500).json({
        erro: 'Erro ao verificar dispositivo',
        detalhe: exErr.message
      });
    }

    // gerar token e código curto
    const tokenPlain = gerarDeviceToken();
    const tokenHash = await hashDeviceToken(tokenPlain);
    const codigoCurto = gerarCodigoCurto();

    // Criar novo dispositivo
    if (!existing) {
      const { data: created, error: createErr } = await supabaseAdmin
        .from('dispositivos')
        .insert({
          nome: nome || null,
          codigo_esp,
          codigo_curto: codigoCurto,
          segredo_hash: null,
          device_token_hash: tokenHash,
          token_revoked: false
        })
        .select('*')
        .single();

      if (createErr) {
        return res.status(500).json({
          erro: 'Falha ao criar dispositivo',
          detalhe: createErr.message
        });
      }

      return res.status(201).json({
        device_id: created.id,
        device_token: tokenPlain,
        codigo_esp: created.codigo_esp,
        codigo_curto: created.codigo_curto
      });
    }

    // Se já existir → reemitir token
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
      return res.status(500).json({
        erro: 'Falha ao atualizar dispositivo',
        detalhe: updErr.message
      });
    }

    return res.status(200).json({
      device_id: upd.id,
      device_token: tokenPlain,
      codigo_esp: upd.codigo_esp,
      codigo_curto: upd.codigo_curto
    });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno ao registrar dispositivo',
      detalhe: e?.message
    });
  }
}

/**
 * POST /device/pair
 */
export async function parearDispositivo(req: ReqWithUser, res: Response) {
  try {
    const usuarioId = req.usuarioId;
    if (!usuarioId) {
      return res.status(401).json({ erro: 'Não autenticado' });
    }

    const { codigo_esp, codigo_curto, assistido_id, pair_code } = req.body;

    if (!codigo_curto && !codigo_esp) {
      return res.status(400).json({
        erro: 'Envie codigo_curto OU codigo_esp'
      });
    }

    if (!assistido_id) {
      return res.status(400).json({
        erro: 'assistido_id é obrigatório'
      });
    }

    // Checar vínculo cuidador → assistido
    const { data: vinculo, error: vincErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select('id')
      .eq('usuario_id', usuarioId)
      .eq('assistido_id', assistido_id)
      .limit(1)
      .maybeSingle();

    if (vincErr) {
      return res.status(500).json({
        erro: 'Falha ao verificar vínculo',
        detalhe: vincErr.message
      });
    }

    if (!vinculo) {
      return res.status(403).json({
        erro: 'Você não está vinculado a esse assistido'
      });
    }

    // Buscar dispositivo por codigo_curto OU codigo_esp
    const filtro = codigo_curto ? { codigo_curto } : { codigo_esp };

    const { data: dispositivo, error: dispErr } = await supabaseAdmin
      .from('dispositivos')
      .select('*')
      .match(filtro)
      .limit(1)
      .maybeSingle();

    if (dispErr) {
      return res.status(500).json({
        erro: 'Erro ao buscar dispositivo',
        detalhe: dispErr.message
      });
    }

    if (!dispositivo) {
      return res.status(404).json({ erro: 'Dispositivo não encontrado' });
    }

    if (dispositivo.assistido_id) {
      return res.status(409).json({ erro: 'Dispositivo já está pareado' });
    }

    // Pair code (se existir)
    if (dispositivo.pair_code_hash) {
      if (!pair_code) {
        return res.status(400).json({ erro: 'pair_code obrigatório' });
      }

      const ok = await bcrypt.compare(pair_code, dispositivo.pair_code_hash);

      if (
        !ok ||
        dispositivo.pair_code_used ||
        (dispositivo.pair_code_expires_at &&
          new Date(dispositivo.pair_code_expires_at) < new Date())
      ) {
        return res.status(403).json({
          erro: 'Pair code inválido ou expirado'
        });
      }
    }

    // Atualização condicional
    const { data: updated, error: updErr } = await supabaseAdmin
      .from('dispositivos')
      .update({
        assistido_id,
        paired_by: usuarioId,
        paired_at: new Date().toISOString()
      })
      .eq('id', dispositivo.id)
      .eq('assistido_id', null)
      .select('*')
      .single();

    if (updErr) {
      return res.status(409).json({
        erro:
          'Falha ao parear: dispositivo pode ter sido pareado por outro usuário',
        detalhe: updErr.message
      });
    }

    return res.json({
      mensagem: 'Pareado com sucesso',
      dispositivo: updated
    });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno ao pareamento',
      detalhe: e?.message
    });
  }
}

/**
 * POST /device/event
 */
export async function registrarEventoDispositivo(req: Request, res: Response) {
  try {
    const device = (req as any).device;
    if (!device) {
      return res.status(401).json({ erro: 'Dispositivo não autenticado' });
    }

    // 🚨 Bloqueia eventos se não estiver pareado
    if (!device.assistido_id) {
      return res.status(400).json({
        erro: 'Dispositivo não pareado — vincule antes de usar.'
      });
    }

    const {
      event_id = null,
      source_timestamp = null,
      event_type = 'queda',
      eixo_x = null,
      eixo_y = null,
      eixo_z = null,
      totalacc = null,
      raw_payload = null
    } = req.body;

    // deduplicação por event_id
    if (event_id) {
      const { data: exists } = await supabaseAdmin
        .from('hist_quedas')
        .select('id')
        .eq('event_id', event_id)
        .limit(1)
        .maybeSingle();

      if (exists) {
        return res.status(200).json({
          ok: true,
          mensagem: 'Evento já registrado'
        });
      }
    }

    // inserir queda
    const { data: inserted, error: insErr } = await supabaseAdmin
      .from('hist_quedas')
      .insert({
        event_id,
        source_timestamp,
        event_type,
        eixo_x,
        eixo_y,
        eixo_z,
        totalacc,
        raw_payload,
        dispositivo_id: device.id,
        assistido_id: device.assistido_id
      })
      .select('*')
      .single();

    if (insErr) {
      return res.status(500).json({
        erro: 'Falha ao registrar evento',
        detalhe: insErr.message
      });
    }

    // atualizar last_seen
    await supabaseAdmin
      .from('dispositivos')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', device.id);

    // ------------------------------------------------------------------
    // 🚀 ENVIO DE PUSH NOTIFICATION PARA TODOS OS CUIDADORES VINCULADOS
    // ------------------------------------------------------------------

    const { data: vinculos, error: vErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select(`
        usuario:usuarios (
          id,
          nome_completo,
          expo_push_token
        )
      `)
      .eq('assistido_id', device.assistido_id);

    if (!vErr && Array.isArray(vinculos)) {
      for (const v of vinculos) {
        const usuario = Array.isArray(v.usuario) ? v.usuario[0] : v.usuario;

        if (usuario?.expo_push_token) {
          try {
            await fetch('https://exp.host/--/api/v2/push/send', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                to: usuario.expo_push_token,
                sound: 'default',
                title: '⚠️ Queda detectada!',
                body: `Uma possível queda foi detectada.`,
                data: {
                  assistido_id: device.assistido_id,
                  evento_id: inserted.id
                }
              })
            });
          } catch (pushErr) {
            console.log('Erro ao enviar push:', pushErr);
          }
        }
      }
    }

    // ------------------------------------------------------------------

    return res.status(201).json({ ok: true, evento: inserted });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno ao registrar evento',
      detalhe: e?.message
    });
  }
}

/**
 * POST /device/heartbeat
 */
export async function heartbeatDispositivo(req: Request, res: Response) {
  try {
    const device = (req as any).device;
    if (!device) {
      return res.status(401).json({ erro: 'Dispositivo não autenticado' });
    }

    await supabaseAdmin
      .from('dispositivos')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', device.id);

    return res.json({ ok: true });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno heartbeat',
      detalhe: e?.message
    });
  }
}

/**
 * GET /device/status
 */
export async function deviceStatus(req: Request, res: Response) {
  try {
    const device = (req as any).device;
    if (!device) {
      return res.status(401).json({ erro: 'Dispositivo não autenticado' });
    }

    const { data: devFresh, error: devErr } = await supabaseAdmin
      .from('dispositivos')
      .select(`
        id,
        codigo_esp,
        codigo_curto,
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
      return res.status(500).json({
        erro: 'Erro ao buscar status do dispositivo',
        detalhe: devErr.message
      });
    }

    if (!devFresh) {
      return res.status(404).json({
        erro: 'Dispositivo não encontrado'
      });
    }

    return res.json({
      pareado: !!devFresh.assistido_id,
      assistido_id: devFresh.assistido_id || null,
      codigo_esp: devFresh.codigo_esp,
      codigo_curto: devFresh.codigo_curto,
      paired_at: devFresh.paired_at || null,
      last_seen: devFresh.last_seen || null,
      nome: devFresh.nome || null,
      firmware_version: devFresh.firmware_version || null
    });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno device status',
      detalhe: e?.message
    });
  }
}

/**
 * POST /device/unpair
 */
export async function unpairDevice(req: ReqWithUser, res: Response) {
  try {
    const usuarioId = req.usuarioId;
    if (!usuarioId) {
      return res.status(401).json({ erro: 'Não autenticado' });
    }

    const { codigo_esp, codigo_curto } = req.body;

    if (!codigo_curto && !codigo_esp) {
      return res.status(400).json({
        erro: 'Envie codigo_curto OU codigo_esp'
      });
    }

    const filtro = codigo_curto ? { codigo_curto } : { codigo_esp };

    const { data: dispositivo, error: dErr } = await supabaseAdmin
      .from('dispositivos')
      .select('*')
      .match(filtro)
      .limit(1)
      .maybeSingle();

    if (dErr) {
      return res.status(500).json({
        erro: 'Erro ao buscar dispositivo',
        detalhe: dErr.message
      });
    }

    if (!dispositivo) {
      return res.status(404).json({
        erro: 'Dispositivo não encontrado'
      });
    }

    if (!dispositivo.assistido_id) {
      return res.status(400).json({
        erro: 'Dispositivo não está pareado'
      });
    }

    // verificar vinculo
    const { data: vinculo, error: vincErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select('id')
      .eq('usuario_id', usuarioId)
      .eq('assistido_id', dispositivo.assistido_id)
      .limit(1)
      .maybeSingle();

    if (vincErr) {
      return res.status(500).json({
        erro: 'Erro ao verificar vínculo',
        detalhe: vincErr.message
      });
    }

    if (!vinculo) {
      return res.status(403).json({
        erro: 'Você não tem permissão para desvincular este dispositivo'
      });
    }

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

    if (updErr) {
      return res.status(500).json({
        erro: 'Falha ao desvincular dispositivo',
        detalhe: updErr.message
      });
    }

    return res.json({
      mensagem: 'Dispositivo desvinculado com sucesso',
      dispositivo: updated
    });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno unpair',
      detalhe: e?.message
    });
  }
}

/**
 * GET /assistidos/:id/quedas
 */
export async function listarQuedasAssistido(req: ReqWithUser, res: Response) {
  try {
    const usuarioId = req.usuarioId;
    if (!usuarioId) {
      return res.status(401).json({ erro: 'Não autenticado' });
    }

    const assistidoId = req.params.id;
    if (!assistidoId) {
      return res.status(400).json({ erro: 'assistido id requerido' });
    }

    // verificar vínculo
    const { data: vinculo, error: vincErr } = await supabaseAdmin
      .from('usuarios_assistidos')
      .select('id')
      .eq('usuario_id', usuarioId)
      .eq('assistido_id', assistidoId)
      .limit(1)
      .maybeSingle();

    if (vincErr) {
      return res.status(500).json({
        erro: 'Erro ao verificar vínculo',
        detalhe: vincErr.message
      });
    }

    if (!vinculo) {
      return res.status(403).json({
        erro: 'Você não está vinculado a esse assistido'
      });
    }

    // paginação
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = Math.min(
      parseInt(req.query.pageSize as string) || 20,
      100
    );
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

    if (qErr) {
      return res.status(500).json({
        erro: 'Erro ao listar quedas',
        detalhe: qErr.message
      });
    }

    return res.json({
      page,
      pageSize,
      items: quedas || []
    });
  } catch (e: any) {
    return res.status(500).json({
      erro: 'Erro interno listar quedas',
      detalhe: e?.message
    });
  }
}
