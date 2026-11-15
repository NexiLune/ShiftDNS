#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

#[derive(Clone, Copy)]
struct Pt {
    x: f32,
    y: f32,
}

fn cubic(p0: Pt, p1: Pt, p2: Pt, p3: Pt, t: f32) -> Pt {
    let u = 1.0 - t;
    let uu = u * u;
    let tt = t * t;
    let uuu = uu * u;
    let ttt = tt * t;
    Pt {
        x: uuu * p0.x + 3.0 * uu * t * p1.x + 3.0 * u * tt * p2.x + ttt * p3.x,
        y: uuu * p0.y + 3.0 * uu * t * p1.y + 3.0 * u * tt * p2.y + ttt * p3.y,
    }
}

fn quad(p0: Pt, p1: Pt, p2: Pt, t: f32) -> Pt {
    let u = 1.0 - t;
    Pt {
        x: u * u * p0.x + 2.0 * u * t * p1.x + t * t * p2.x,
        y: u * u * p0.y + 2.0 * u * t * p1.y + t * t * p2.y,
    }
}

fn shield_polygon() -> Vec<Pt> {
    let mut pts = Vec::with_capacity(72);
    let steps = 8;

    // Right side straight segment: (20, 6) -> (20, 13)
    pts.push(Pt { x: 20.0, y: 6.0 });
    pts.push(Pt { x: 20.0, y: 13.0 });

    // Bottom-right cubic: M20 13 c0 5 -3.5 7.5 -7.66 8.95
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        pts.push(cubic(
            Pt { x: 20.0, y: 13.0 },
            Pt { x: 20.0, y: 18.0 },
            Pt { x: 16.5, y: 20.5 },
            Pt { x: 12.34, y: 21.95 },
            t,
        ));
    }

    // Bottom tip arc: a1 1 0 0 1 -.67 -.01
    pts.push(quad(
        Pt { x: 12.34, y: 21.95 },
        Pt { x: 12.0, y: 22.05 },
        Pt { x: 11.67, y: 21.94 },
        0.5,
    ));
    pts.push(Pt { x: 11.67, y: 21.94 });

    // Bottom-left cubic: C7.5 20.5 4 18 4 13
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        pts.push(cubic(
            Pt { x: 11.67, y: 21.94 },
            Pt { x: 7.5, y: 20.5 },
            Pt { x: 4.0, y: 18.0 },
            Pt { x: 4.0, y: 13.0 },
            t,
        ));
    }

    // Left straight segment: V6 + rounded top-left corner a1 1 0 0 1 1 -1
    pts.push(Pt { x: 4.0, y: 6.0 });
    pts.push(quad(
        Pt { x: 4.0, y: 6.0 },
        Pt { x: 4.0, y: 5.0 },
        Pt { x: 5.0, y: 5.0 },
        0.5,
    ));
    pts.push(Pt { x: 5.0, y: 5.0 });

    // Top-left cubic: c2 0 4.5 -1.2 6.24 -2.72
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        pts.push(cubic(
            Pt { x: 5.0, y: 5.0 },
            Pt { x: 7.0, y: 5.0 },
            Pt { x: 9.5, y: 3.8 },
            Pt { x: 11.24, y: 2.28 },
            t,
        ));
    }

    // Top peak arc: a1.17 1.17 0 0 1 1.52 0
    pts.push(quad(
        Pt { x: 11.24, y: 2.28 },
        Pt { x: 12.0, y: 1.88 },
        Pt { x: 12.76, y: 2.28 },
        0.5,
    ));
    pts.push(Pt { x: 12.76, y: 2.28 });

    // Top-right cubic: C14.51 3.81 17 5 19 5
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        pts.push(cubic(
            Pt { x: 12.76, y: 2.28 },
            Pt { x: 14.51, y: 3.81 },
            Pt { x: 17.0, y: 5.0 },
            Pt { x: 19.0, y: 5.0 },
            t,
        ));
    }

    // Top-right rounded corner: a1 1 0 0 1 1 1
    pts.push(quad(
        Pt { x: 19.0, y: 5.0 },
        Pt { x: 20.0, y: 5.0 },
        Pt { x: 20.0, y: 6.0 },
        0.5,
    ));

    pts
}

fn dist_sq_to_segment(px: f32, py: f32, a: Pt, b: Pt) -> f32 {
    let dx = b.x - a.x;
    let dy = b.y - a.y;
    let len_sq = dx * dx + dy * dy;
    if len_sq <= 1e-6 {
        let vx = px - a.x;
        let vy = py - a.y;
        return vx * vx + vy * vy;
    }
    let t = (((px - a.x) * dx + (py - a.y) * dy) / len_sq).clamp(0.0, 1.0);
    let qx = a.x + t * dx;
    let qy = a.y + t * dy;
    let ex = px - qx;
    let ey = py - qy;
    ex * ex + ey * ey
}

fn point_in_polygon(px: f32, py: f32, poly: &[Pt]) -> bool {
    let mut inside = false;
    let n = poly.len();
    let mut j = n - 1;
    for i in 0..n {
        let pi = poly[i];
        let pj = poly[j];
        let intersects = ((pi.y > py) != (pj.y > py))
            && (px < (pj.x - pi.x) * (py - pi.y) / (pj.y - pi.y + 1e-9) + pi.x);
        if intersects {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn min_edge_distance(px: f32, py: f32, poly: &[Pt]) -> f32 {
    let mut best = f32::MAX;
    let n = poly.len();
    let mut j = n - 1;
    for i in 0..n {
        let d = dist_sq_to_segment(px, py, poly[j], poly[i]);
        if d < best {
            best = d;
        }
        j = i;
    }
    best.sqrt()
}

fn sd_rounded_box(px: f32, py: f32, center: f32, half: f32, radius: f32) -> f32 {
    let qx = (px - center).abs() - (half - radius);
    let qy = (py - center).abs() - (half - radius);
    let ox = qx.max(0.0);
    let oy = qy.max(0.0);
    (ox * ox + oy * oy).sqrt() + qx.max(qy).min(0.0) - radius
}

fn blend_over(dst: [f32; 4], src: [f32; 4]) -> [f32; 4] {
    let sa = src[3];
    if sa <= 1e-6 {
        return dst;
    }
    let da = dst[3];
    let out_a = sa + da * (1.0 - sa);
    if out_a <= 1e-6 {
        return [0.0; 4];
    }
    [
        (src[0] * sa + dst[0] * da * (1.0 - sa)) / out_a,
        (src[1] * sa + dst[1] * da * (1.0 - sa)) / out_a,
        (src[2] * sa + dst[2] * da * (1.0 - sa)) / out_a,
        out_a,
    ]
}

/// Native Windows 11 app & taskbar icon: crisp anti-aliased dark squircle tile (#121417)
/// with a subtle 1px border (#262930) and centered, slightly bolder white Shield glyph.
pub fn generate_app_icon_rgba(size: u32) -> Vec<u8> {
    let poly = shield_polygon();
    let mut out = vec![0u8; (size * size * 4) as usize];
    let scale = 24.0 / (size as f32);
    let aa = scale * 0.85;

    // Rounded-square tile geometry in 24x24 space
    let tile_half = 11.0_f32;
    let tile_radius = 5.2_f32;
    let border_px = (size as f32 / 32.0).clamp(1.0, 5.0);
    let border_24 = border_px * scale;

    let tile_fill = [18.0 / 255.0, 20.0 / 255.0, 23.0 / 255.0]; // #121417
    let tile_border = [38.0 / 255.0, 41.0 / 255.0, 48.0 / 255.0]; // #262930

    // Centered Shield geometry scaled smoothly inside the squircle
    let shield_scale = 0.60_f32;
    let half_stroke = if size <= 20 { 1.50 } else { 1.35 };
    let aa_shield = aa / shield_scale;
    let sub = 2;
    let samples = (sub * sub) as f32;

    for y in 0..size {
        for x in 0..size {
            let mut accum = [0.0_f32; 4];
            for sy in 0..sub {
                for sx in 0..sub {
                    let px = (x as f32 + (sx as f32 + 0.5) / sub as f32) * scale;
                    let py = (y as f32 + (sy as f32 + 0.5) / sub as f32) * scale;

                    let tile_sdf = sd_rounded_box(px, py, 12.0, tile_half, tile_radius);
                    let tile_cov = (0.5 - tile_sdf / aa).clamp(0.0, 1.0);
                    if tile_cov <= 1e-4 {
                        continue;
                    }

                    let inner_cov = (0.5 - (tile_sdf + border_24) / aa).clamp(0.0, 1.0);
                    let mut sample = [
                        tile_border[0] * (1.0 - inner_cov) + tile_fill[0] * inner_cov,
                        tile_border[1] * (1.0 - inner_cov) + tile_fill[1] * inner_cov,
                        tile_border[2] * (1.0 - inner_cov) + tile_fill[2] * inner_cov,
                        tile_cov,
                    ];

                    // Transform sample point into centered Shield local 24x24 coordinates
                    let lx = (px - 12.0) / shield_scale + 12.0;
                    let ly = (py - 12.0) / shield_scale + 12.0;

                    // Quick-reject outside shield bounds to keep build.rs instant at 256x256
                    if (0.5..=23.5).contains(&lx) && (0.0..=24.0).contains(&ly) {
                        let inside = point_in_polygon(lx, ly, &poly);
                        let edge_d = min_edge_distance(lx, ly, &poly);

                        let poly_sdf = if inside { -edge_d } else { edge_d };
                        let fill_cov = (0.5 - poly_sdf / aa_shield).clamp(0.0, 1.0);
                        if fill_cov > 1e-4 {
                            sample = blend_over(sample, [1.0, 1.0, 1.0, 0.14 * fill_cov]);
                        }

                        let stroke_sdf = edge_d - half_stroke;
                        let stroke_cov = (0.5 - stroke_sdf / aa_shield).clamp(0.0, 1.0);
                        if stroke_cov > 1e-4 {
                            sample = blend_over(sample, [1.0, 1.0, 1.0, stroke_cov]);
                        }
                    }

                    accum[0] += sample[0] * sample[3];
                    accum[1] += sample[1] * sample[3];
                    accum[2] += sample[2] * sample[3];
                    accum[3] += sample[3];
                }
            }

            let a = accum[3] / samples;
            let idx = ((y * size + x) * 4) as usize;
            if a > 1e-4 {
                out[idx] = ((accum[0] / accum[3]).clamp(0.0, 1.0) * 255.0).round() as u8;
                out[idx + 1] = ((accum[1] / accum[3]).clamp(0.0, 1.0) * 255.0).round() as u8;
                out[idx + 2] = ((accum[2] / accum[3]).clamp(0.0, 1.0) * 255.0).round() as u8;
                out[idx + 3] = (a.clamp(0.0, 1.0) * 255.0).round() as u8;
            }
        }
    }

    out
}

/// Minimal concentric circle tray icon:
/// - Active resolver: crisp anti-aliased white ring with a solid emerald green center dot (#10B981).
/// - System Default / DHCP: muted gray ring (#94A3B8) with no center dot.
pub fn generate_tray_ring_rgba(size: u32, custom_active: bool) -> Vec<u8> {
    let mut out = vec![0u8; (size * size * 4) as usize];
    let scale = 24.0 / (size as f32);
    let aa = scale * 0.88;

    let ring_r = 8.8_f32;
    let ring_half_w = 1.75_f32;
    let dot_r = 4.1_f32;

    let ring_rgb = if custom_active {
        [1.0_f32, 1.0, 1.0]
    } else {
        [148.0 / 255.0, 163.0 / 255.0, 184.0 / 255.0] // #94A3B8
    };
    let dot_rgb = [16.0 / 255.0, 185.0 / 255.0, 129.0 / 255.0]; // #10B981

    let sub = 2;
    let samples = (sub * sub) as f32;

    for y in 0..size {
        for x in 0..size {
            let mut accum = [0.0_f32; 4];
            for sy in 0..sub {
                for sx in 0..sub {
                    let px = (x as f32 + (sx as f32 + 0.5) / sub as f32) * scale - 12.0;
                    let py = (y as f32 + (sy as f32 + 0.5) / sub as f32) * scale - 12.0;
                    let r = (px * px + py * py).sqrt();

                    let ring_sdf = (r - ring_r).abs() - ring_half_w;
                    let ring_cov = (0.5 - ring_sdf / aa).clamp(0.0, 1.0);

                    let mut sample = [0.0_f32; 4];
                    if ring_cov > 1e-4 {
                        sample = blend_over(sample, [ring_rgb[0], ring_rgb[1], ring_rgb[2], ring_cov]);
                    }

                    if custom_active {
                        let dot_sdf = r - dot_r;
                        let dot_cov = (0.5 - dot_sdf / aa).clamp(0.0, 1.0);
                        if dot_cov > 1e-4 {
                            sample = blend_over(sample, [dot_rgb[0], dot_rgb[1], dot_rgb[2], dot_cov]);
                        }
                    }

                    accum[0] += sample[0] * sample[3];
                    accum[1] += sample[1] * sample[3];
                    accum[2] += sample[2] * sample[3];
                    accum[3] += sample[3];
                }
            }

            let a = accum[3] / samples;
            let idx = ((y * size + x) * 4) as usize;
            if a > 1e-4 {
                out[idx] = ((accum[0] / accum[3]).clamp(0.0, 1.0) * 255.0).round() as u8;
                out[idx + 1] = ((accum[1] / accum[3]).clamp(0.0, 1.0) * 255.0).round() as u8;
                out[idx + 2] = ((accum[2] / accum[3]).clamp(0.0, 1.0) * 255.0).round() as u8;
                out[idx + 3] = (a.clamp(0.0, 1.0) * 255.0).round() as u8;
            }
        }
    }

    out
}

/// Writes a multi-size 32-bit BGRA Windows `.ico` file (`16, 32, 48, 256` px) without external crates.
pub fn write_ico_file(path: &Path) -> io::Result<()> {
    let sizes: [u32; 4] = [16, 32, 48, 256];
    let mut images: Vec<(u32, Vec<u8>)> = Vec::with_capacity(sizes.len());

    for &size in &sizes {
        let rgba = generate_app_icon_rgba(size);
        let and_row_bytes = (((size + 31) / 32) * 4) as usize;
        let and_bytes = and_row_bytes * size as usize;
        let pixel_bytes = (size * size * 4) as usize;
        let mut dib = Vec::with_capacity(40 + pixel_bytes + and_bytes);

        // BITMAPINFOHEADER (40 bytes)
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&(size as i32).to_le_bytes()); // biWidth
        dib.extend_from_slice(&((size * 2) as i32).to_le_bytes()); // biHeight (XOR + AND)
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
        dib.extend_from_slice(&(pixel_bytes as u32).to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

        // Bottom-up BGRA pixel data
        for y in (0..size).rev() {
            for x in 0..size {
                let idx = ((y * size + x) * 4) as usize;
                dib.push(rgba[idx + 2]); // B
                dib.push(rgba[idx + 1]); // G
                dib.push(rgba[idx]); // R
                dib.push(rgba[idx + 3]); // A
            }
        }

        // 1-bpp AND mask (all 0s; 32-bit alpha controls transparency)
        dib.resize(40 + pixel_bytes + and_bytes, 0);
        images.push((size, dib));
    }

    let mut ico = Vec::new();
    // ICONDIR
    ico.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // idType (1 = ICO)
    ico.extend_from_slice(&(images.len() as u16).to_le_bytes()); // idCount

    let mut offset = 6 + images.len() * 16;
    for (size, dib) in &images {
        // In Windows ICO headers, 0 represents 256 pixels.
        let dim_byte = if *size >= 256 { 0u8 } else { *size as u8 };
        ico.push(dim_byte); // bWidth
        ico.push(dim_byte); // bHeight
        ico.push(0); // bColorCount
        ico.push(0); // bReserved
        ico.extend_from_slice(&1u16.to_le_bytes()); // wPlanes
        ico.extend_from_slice(&32u16.to_le_bytes()); // wBitCount
        ico.extend_from_slice(&(dib.len() as u32).to_le_bytes()); // dwBytesInRes
        ico.extend_from_slice(&(offset as u32).to_le_bytes()); // dwImageOffset
        offset += dib.len();
    }

    for (_, dib) in images {
        ico.extend_from_slice(&dib);
    }

    let mut file = File::create(path)?;
    file.write_all(&ico)?;
    Ok(())
}
