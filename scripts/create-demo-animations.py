"""Render the educational SQLi request paths as silent, presentation-ready MP4s.

No application request or SQL statement is executed by this renderer.
The MLP clip illustrates a conditional decision, not a measured prediction.
"""
from __future__ import annotations

from functools import lru_cache
import json
import math
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.runtime' / 'animation-deps'))
import imageio_ffmpeg
import numpy as np
from PIL import Image, ImageDraw, ImageFont

OUT = ROOT / 'output' / 'animations'
BUILD = ROOT / 'tmp' / 'animation-build'
W, H, FPS = 1920, 1080, 20
BG, PAPER, INK = '#F1EFE8', '#FAF9F4', '#29332E'
GREEN, RED, AMBER = '#285C4D', '#A14536', '#996B32'
MUTED, LINE, FAINT = '#68746C', '#C8CEC5', '#E2E3DA'
FONT_DIR = Path('C:/Windows/Fonts')
INPUT_RULE = "' OR 1=1 -- "
INPUT_MLP = "' OR 'b' > 'a' -- "
CLIPS = [
    ('vulnerable', '01_site_vulnerable.mp4', 16),
    ('rules', '02_blocage_regles.mp4', 18),
    ('mlp', '03_decision_mlp.mp4', 22),
]


@lru_cache(maxsize=80)
def font(size, role='body'):
    filename = {'body': 'segoeui.ttf', 'bold': 'seguisb.ttf',
                'title': 'georgia.ttf', 'code': 'consola.ttf'}[role]
    return ImageFont.truetype(str(FONT_DIR / filename), size)


def text(d, xy, value, size=26, color=INK, role='body', anchor=None):
    d.text(xy, str(value), font=font(size, role), fill=color, anchor=anchor)


def lines(d, xy, value, size=25, color=INK, role='body', gap=11):
    x, y = xy
    for line in value.split('\n'):
        text(d, (x, y), line, size, color, role)
        y += size + gap


def arrow(d, points, color=LINE, width=4, head=True, dashed=False):
    if dashed:
        for a, b in zip(points, points[1:]):
            distance = math.dist(a, b)
            for pos in range(0, int(distance), 19):
                q0, q1 = pos / distance, min(pos + 9, distance) / distance
                d.line([(a[0] + (b[0] - a[0]) * q0, a[1] + (b[1] - a[1]) * q0),
                        (a[0] + (b[0] - a[0]) * q1, a[1] + (b[1] - a[1]) * q1)], fill=color, width=width)
    else:
        d.line(points, fill=color, width=width, joint='curve')
    if head:
        end, before = points[-1], points[-2]
        angle = math.atan2(end[1] - before[1], end[0] - before[0])
        corners = [end]
        for delta in (-0.49, 0.49):
            corners.append((end[0] - 15 * math.cos(angle + delta), end[1] - 15 * math.sin(angle + delta)))
        d.polygon(corners, fill=color)


def point_at(points, fraction):
    lengths = [math.dist(a, b) for a, b in zip(points, points[1:])]
    remaining = sum(lengths) * max(0, min(1, fraction))
    for a, b, length in zip(points, points[1:], lengths):
        if remaining <= length:
            p = remaining / length if length else 0
            return a[0] + (b[0] - a[0]) * p, a[1] + (b[1] - a[1]) * p
        remaining -= length
    return points[-1]


def packet(d, points, progress, label='HTTP', color=RED):
    x, y = point_at(points, progress)
    d.rounded_rectangle((x-45, y-24, x+45, y+24), radius=5, fill=color)
    text(d, (x, y-1), label, 19, PAPER, 'bold', 'mm')


def browser(d, x, active=True):
    color = INK if active else LINE
    d.rounded_rectangle((x-90, 420, x+90, 550), radius=7, fill=PAPER, outline=color, width=3)
    d.line((x-90, 447, x+90, 447), fill=color, width=2)
    for p in range(3):
        d.ellipse((x-73+p*16, 430, x-67+p*16, 436), fill=color)
    d.line((x-64, 477, x+57, 477), fill=color, width=4)
    d.line((x-64, 495, x+32, 495), fill=LINE, width=4)
    d.line((x-64, 513, x+45, 513), fill=LINE, width=4)


def module(d, x, label, active=False, blocked=False):
    color = RED if blocked else GREEN if active else LINE
    d.rounded_rectangle((x-90, 420, x+90, 550), radius=6, fill=PAPER, outline=color, width=4 if active or blocked else 3)
    text(d, (x, 484), label, 32 if len(label) < 5 else 25, color, 'bold', 'mm')


def database(d, x, active=False):
    color = RED if active else LINE
    d.rectangle((x-70, 434, x+70, 532), fill=PAPER)
    d.line((x-70, 434, x-70, 532), fill=color, width=3)
    d.line((x+70, 434, x+70, 532), fill=color, width=3)
    d.arc((x-70, 510, x+70, 550), 0, 180, fill=color, width=3)
    d.ellipse((x-70, 414, x+70, 454), fill=PAPER, outline=color, width=3)
    d.arc((x-70, 458, x+70, 498), 0, 180, fill=color, width=2)
    d.arc((x-70, 486, x+70, 526), 0, 180, fill=color, width=2)


def mlp_icon(d, active=False):
    color = GREEN if active else LINE
    cols = [(610, [757, 800, 843]), (685, [742, 780, 820, 858]), (760, [775, 825])]
    for (x0, ys0), (x1, ys1) in zip(cols, cols[1:]):
        for y0 in ys0:
            for y1 in ys1:
                d.line((x0, y0, x1, y1), fill=LINE, width=2)
    for x, ys in cols:
        for y in ys:
            d.ellipse((x-9, y-9, x+9, y+9), fill=PAPER, outline=color, width=3)


def label(d, x, title, subtitle, active=True):
    text(d, (x, 592), title, 27, INK if active else MUTED, 'bold', 'mm')
    text(d, (x, 631), subtitle, 22, MUTED, anchor='mm')


def phase_for(kind, t):
    borders = {'vulnerable': [3, 6, 10, 13], 'rules': [3, 6, 9, 12, 15],
               'mlp': [3, 6, 9, 12, 15, 18, 20]}[kind]
    return sum(t >= mark for mark in borders)


@lru_cache(maxsize=40)
def base_frame(kind, phase):
    image = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(image)
    index = {'vulnerable': '01', 'rules': '02', 'mlp': '03'}[kind]
    text(d, (96, 54), 'CYBERSHIELD AI  /  PARCOURS D’UNE REQUÊTE', 20, GREEN, 'bold')
    text(d, (1824, 54), index + ' / 03', 21, MUTED, anchor='ra')
    titles = {'vulnerable': 'Une saisie devient du SQL',
              'rules': 'La signature arrête la requête',
              'mlp': 'Le MLP complète l’analyse'}
    text(d, (96, 102), titles[kind], 57, INK, 'title')
    subtitles = {'vulnerable': 'Site vulnérable · construction SQL par concaténation',
                 'rules': 'CyberShield AI · détection déterministe par les règles',
                 'mlp': 'CyberShield AI · parcours conditionnel d’un cas à examiner'}
    text(d, (98, 181), subtitles[kind], 25, MUTED)
    if kind != 'vulnerable':
        text(d, (1824, 185), 'SCÉNARIO EN MODE BLOCAGE', 19, GREEN, 'bold', 'ra')
    stages = {
        'vulnerable': ['La valeur est saisie dans un formulaire', 'Le paramètre est envoyé en HTTP',
                       'L’application concatène la valeur dans le SQL', 'La requête modifiée atteint MariaDB',
                       'La condition OR 1=1 élargit le résultat'],
        'rules': ['La même valeur est saisie dans le formulaire', 'Le paramètre arrive au filtre PHP',
                  'La signature NUMERIC_BOOLEAN est reconnue', '90 / 100 : le seuil de 80 est dépassé',
                  'Une réponse HTTP 403 revient au navigateur', 'La décision finale est journalisée'],
        'mlp': ['Une autre saisie présente un signal à examiner', 'Le paramètre arrive au filtre PHP',
                'Score de règles : 60 / 100, dans la zone d’analyse', 'Le filtre appelle le service MLP Python',
                'Le MLP calcule un score comparé au seuil de 0,75', 'Si le score atteint 0,75, la décision est de bloquer',
                'En mode blocage, le filtre renvoie HTTP 403', 'Cette branche s’arrête avant l’accès SQL'],
    }
    text(d, (98, 239), f'{phase+1:02d}  {stages[kind][phase]}', 28, INK, 'bold')
    text(d, (99, 296), 'SAISIE UTILISATEUR · VALEUR D’UN PARAMÈTRE HTTP', 16, MUTED, 'bold')
    d.rounded_rectangle((96, 326, 1824, 384), radius=4, outline=LINE, width=2, fill=PAPER)
    if kind == 'vulnerable':
        xs = [235, 960, 1685]
        browser(d, xs[0])
        module(d, xs[1], 'PHP', phase >= 2)
        database(d, xs[2], phase >= 3)
        arrow(d, [(330, 485), (865, 485)], RED if phase >= 1 else LINE)
        arrow(d, [(1055, 485), (1610, 485)], RED if phase >= 3 else LINE)
        text(d, (595, 446), 'HTTP + paramètre', 21, MUTED, anchor='mm')
        text(d, (1330, 446), 'Requête SQL', 21, MUTED, anchor='mm')
        label(d, xs[0], 'Navigateur', 'Valeur de formulaire')
        label(d, xs[1], 'Application PHP', 'SQL construit par concaténation')
        label(d, xs[2], 'MariaDB', 'La base exécute le SQL reçu', phase >= 3)
        d.line((96, 695, 1824, 695), fill=LINE, width=2)
        text(d, (98, 719), 'REQUÊTE CONSTRUITE PAR LE SITE VULNÉRABLE', 18, MUTED, 'bold')
        if phase >= 2:
            lines(d, (98, 760), "SELECT id, username\nFROM users\nWHERE username = '' OR 1=1 -- ';", 31, INK, 'code', 9)
            if phase >= 4:
                text(d, (1190, 780), '1=1 est toujours vrai', 33, RED, 'bold')
                text(d, (1190, 835), 'Le résultat dépasse la recherche prévue.', 23, MUTED)
        else:
            text(d, (98, 773), 'La saisie n’est pas encore devenue une requête SQL.', 29, MUTED)
        text(d, (98, 991), 'Comparaison pédagogique fictive. Aucune requête SQL n’est exécutée par cette vidéo.', 20, MUTED)
        text(d, (98, 1023), 'HTTP va du navigateur à l’application ; seule l’application adresse du SQL à la base.', 20, MUTED)
    else:
        xs = [205, 685, 1165, 1645]
        blocked = phase >= (3 if kind == 'rules' else 5)
        browser(d, xs[0])
        module(d, xs[1], 'FILTRE', phase >= 1, blocked)
        module(d, xs[2], 'SQL lié')
        database(d, xs[3])
        arrow(d, [(300, 485), (590, 485)], RED if phase >= 1 else LINE)
        arrow(d, [(780, 485), (1070, 485)], LINE, dashed=True)
        arrow(d, [(1260, 485), (1570, 485)], LINE, dashed=True)
        label(d, xs[0], 'Navigateur', 'Paramètre HTTP')
        label(d, xs[1], 'Filtre PHP', 'Règles puis politique de décision')
        label(d, xs[2], 'Application métier', 'Requêtes préparées', False)
        label(d, xs[3], 'MariaDB', 'Non atteinte dans la branche bloquée', False)
        if blocked:
            d.line((930, 456, 930, 514), fill=RED, width=8)
            text(d, (930, 540), 'ARRÊT', 19, RED, 'bold', 'mm')
        if kind == 'rules':
            d.line((96, 695, 1824, 695), fill=LINE, width=2)
            text(d, (98, 724), 'DÉCISION PAR LES RÈGLES', 18, GREEN, 'bold')
            if phase >= 2:
                text(d, (98, 775), 'NUMERIC_BOOLEAN', 38, INK, 'code')
                text(d, (98, 836), 'Score 90 / 100 · seuil de blocage 80', 29, RED if blocked else MUTED)
                text(d, (1110, 775), 'MLP non appelé', 34, GREEN, 'bold')
                text(d, (1110, 831), 'La signature suffit pour ce parcours.', 24, MUTED)
            else:
                text(d, (98, 778), 'Une signature explicite sera recherchée avant tout appel au MLP.', 29, MUTED)
            if phase >= 5:
                text(d, (98, 907), 'source=heuristic    action=BLOCKED    réponse=403', 24, GREEN, 'code')
            text(d, (98, 991), 'Scénario en mode blocage. En mode observation, le signal est consigné sans blocage SQLi.', 20, MUTED)
            text(d, (98, 1023), 'La saisie bloquée n’atteint pas la base. Le LLM de l’assistant ne prend aucune décision de filtrage.', 20, MUTED)
        else:
            to_mlp = [(640, 550), (475, 550), (475, 800), (580, 800)]
            from_mlp = [(790, 800), (895, 800), (895, 550), (730, 550)]
            arrow(d, to_mlp, GREEN if phase >= 3 else LINE, 3)
            arrow(d, from_mlp, GREEN if phase >= 5 else LINE, 3)
            mlp_icon(d, phase >= 3)
            text(d, (685, 910), 'MLP Python', 26, INK, 'bold', 'mm')
            text(d, (685, 948), 'Caractéristiques → score', 22, MUTED, anchor='mm')
            text(d, (1020, 722), 'DÉCISION CONDITIONNELLE', 18, GREEN, 'bold')
            if phase >= 4:
                text(d, (1020, 767), 'Score MLP ≥ 0,75 ?', 39, INK, 'bold')
                text(d, (1020, 831), 'OUI → blocage dans la branche illustrée', 26, RED)
                text(d, (1020, 875), 'NON → poursuite avec requêtes préparées', 24, MUTED)
            else:
                text(d, (1020, 774), 'Un signal ambigu demande\nune analyse complémentaire.', 28, MUTED)
            text(d, (98, 995), 'Branche illustrée, sans score de prédiction inventé. Le score MLP n’est pas une probabilité calibrée.', 20, MUTED)
            text(d, (98, 1027), 'Blocage effectif uniquement en mode blocage ; décision finale journalisée. Le LLM reste hors de ce chemin.', 20, MUTED)
    return image


def frame(kind, t, duration):
    phase = phase_for(kind, t)
    image = base_frame(kind, phase).copy()
    d = ImageDraw.Draw(image)
    payload = INPUT_MLP if kind == 'mlp' else INPUT_RULE
    progress = max(0, min(1, t / 2.5))
    shown = payload[:int(len(payload) * progress)]
    text(d, (120, 337), shown + ('|' if t < 3 and int(t*3) % 2 == 0 else ''), 29, RED, 'code')
    if kind == 'vulnerable':
        if 3 <= t < 6:
            packet(d, [(330, 485), (865, 485)], (t-3)/3)
        if 10 <= t < 13:
            packet(d, [(1055, 485), (1610, 485)], (t-10)/3, 'SQL')
    else:
        if 3 <= t < 6:
            packet(d, [(300, 485), (590, 485)], (t-3)/3)
        if kind == 'mlp':
            if 9 <= t < 12:
                packet(d, [(640, 550), (475, 550), (475, 800), (580, 800)], (t-9)/3, 'MLP', GREEN)
            if 15 <= t < 18:
                packet(d, [(790, 800), (895, 800), (895, 550), (730, 550)], (t-15)/3, 'Score', GREEN)
        response_start = 12 if kind == 'rules' else 18
        if response_start <= t < response_start + (3 if kind == 'rules' else 2):
            path = [(685, 411), (685, 402), (205, 402), (205, 411)]
            arrow(d, path, RED, 2)
            packet(d, path, (t-response_start)/(3 if kind == 'rules' else 2), '403')
        elif t >= response_start:
            text(d, (445, 406), 'HTTP 403 · requête bloquée', 21, RED, 'bold', 'mm')
    d.line((96, 1060, 1824, 1060), fill=FAINT, width=4)
    d.line((96, 1060, 96 + int(1728 * min(t / duration, 1)), 1060), fill=GREEN, width=4)
    return image


def render_clip(kind, filename, duration):
    target = OUT / filename
    writer = imageio_ffmpeg.write_frames(str(target), (W, H), fps=FPS, codec='libx264',
        pix_fmt_in='rgb24', pix_fmt_out='yuv420p', output_params=['-crf', '20', '-preset', 'veryfast', '-movflags', '+faststart'],
        ffmpeg_log_level='error', macro_block_size=8)
    writer.send(None)
    try:
        for index in range(duration * FPS):
            writer.send(np.asarray(frame(kind, index / FPS, duration)))
    finally:
        writer.close()
    final = frame(kind, duration - .05, duration)
    final.save(OUT / (Path(filename).stem + '.png'))
    for phase, time in enumerate({'vulnerable': [1, 4.5, 8, 11.5, 15],
                                 'rules': [1, 4.5, 7.5, 10.5, 13.5, 17],
                                 'mlp': [1, 4.5, 7.5, 10.5, 13.5, 16.5, 19, 21]}[kind]):
        frame(kind, time, duration).save(BUILD / f'{kind}-phase-{phase+1:02d}.png')
    count, seconds = imageio_ffmpeg.count_frames_and_secs(str(target))
    if count != duration * FPS or abs(seconds-duration) > .1:
        raise RuntimeError(f'Video duration/frame mismatch: {filename}: {count}, {seconds}')
    print(json.dumps({'file': filename, 'seconds': seconds, 'frames': count, 'bytes': target.stat().st_size}), flush=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    for kind, filename, duration in CLIPS:
        render_clip(kind, filename, duration)
    filelist = BUILD / 'concat.txt'
    filelist.write_text(''.join("file '" + str((OUT / filename).resolve()).replace('\\', '/') + "'\n" for _, filename, _ in CLIPS), encoding='utf-8')
    combined = OUT / '00_comparaison_complete_56s.mp4'
    subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), '-y', '-v', 'error', '-f', 'concat', '-safe', '0',
                    '-i', str(filelist), '-c', 'copy', '-movflags', '+faststart', str(combined)], check=True)
    count, seconds = imageio_ffmpeg.count_frames_and_secs(str(combined))
    if count != 56 * FPS or abs(seconds-56) > .1:
        raise RuntimeError('Combined video validation failed.')
    thumbnails = []
    for kind, _, duration in CLIPS:
        for time in [1, duration*.43, duration*.7, duration-.1]:
            thumbnails.append(frame(kind, time, duration).resize((480, 270), Image.Resampling.LANCZOS))
    sheet = Image.new('RGB', (1920, 810), BG)
    for i, thumb in enumerate(thumbnails):
        sheet.paste(thumb, ((i%4)*480, (i//4)*270))
    sheet.save(BUILD / 'contact-sheet.png')
    print(json.dumps({'combined': combined.name, 'seconds': seconds, 'frames': count}), flush=True)


if __name__ == '__main__':
    main()
