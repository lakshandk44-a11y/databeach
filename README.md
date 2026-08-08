---

## GitHub upload + run

```bash
git init
git add databeach.py platforms.json requirements.txt README.md data/
git commit -m "Data Beach v1.0"
git remote add origin https://github.com/<YOUR_USER>/data-beach.git
git push -u origin main

# ඕනම terminal එකක:
git clone https://github.com/<YOUR_USER>/data-beach.git
cd data-beach
pip install -r requirements.txt
python databeach.py
