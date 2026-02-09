# Screenshot Guide

## Required Screenshots

Add these 3 screenshots to the `docs/` folder:

### 1. battle_demo.png
**What:** Terminal showing Red vs Blue Team battle
**How to capture:**
```bash
python demo_live.py
# Wait for colorful battle animation
# Screenshot the terminal when both teams are shown
# Save as docs/battle_demo.png
```
**Size:** Keep under 500KB (compress if needed)

### 2. dashboard.png
**What:** Gradio web interface
**How to capture:**
```bash
python dashboard/app.py
# Open http://localhost:7860 in browser
# Screenshot the full interface showing:
  - AI chatbot interface
  - Dashboard features
  - Professional UI
# Save as docs/dashboard.png
```
**Size:** Keep under 500KB

### 3. attack_chain.png
**What:** Attack chain visualization
**How to capture:**
```bash
python demo_attack_chains.py
# Screenshot the attack chain diagram/visualization
# OR create a simple diagram showing:
  User Input → Auth Bypass → SQL Injection → RCE
# Save as docs/attack_chain.png
```
**Size:** Keep under 500KB

## Quick Tips

- Use **Windows Snipping Tool** (Win+Shift+S) or **Snip & Sketch**
- Use **lightshot** or **ShareX** for easy screenshots
- Compress images: https://tinypng.com/
- Make sure text is readable at 800px width
- Include colorful, visually appealing shots

## Verify Screenshots Work

After adding, check that images load in README:
```bash
# Open README in browser or VS Code preview
# Images should show at line ~60
```

All done? ✅ Check off in [WINNING_TASKS.md](../WINNING_TASKS.md)
