"""
Merge surrogate feature importances CSV into latest family evaluation JSON/text report
and produce a comparative bar plot saved under `evaluation_reports/feature_importance_lofo_plot.png`.
"""
import os
import json
import glob
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(ROOT, "evaluation_reports")

# find latest JSON and latest CSV
json_files = sorted(glob.glob(os.path.join(REPORT_DIR, 'family_evaluation_*.json')))
csv_files = sorted(glob.glob(os.path.join(REPORT_DIR, 'feature_importance_lofo_*.csv')))
text_files = sorted(glob.glob(os.path.join(REPORT_DIR, 'family_evaluation_*.txt')))

if not json_files:
    raise SystemExit('No family_evaluation JSON found in evaluation_reports')
if not csv_files:
    raise SystemExit('No feature_importance_lofo CSV found in evaluation_reports')
if not text_files:
    raise SystemExit('No family_evaluation TXT found in evaluation_reports')

latest_json = json_files[-1]
latest_csv = csv_files[-1]
latest_txt = text_files[-1]

print(f"Using JSON: {os.path.basename(latest_json)}")
print(f"Using CSV:  {os.path.basename(latest_csv)}")
print(f"Using TXT:  {os.path.basename(latest_txt)}")

# load json
with open(latest_json, 'r', encoding='utf-8') as f:
    data = json.load(f)

# load csv
df_imp = pd.read_csv(latest_csv)

# merge into JSON under key 'surrogate_feature_importance'
data['surrogate_feature_importance'] = df_imp.to_dict(orient='records')

# save updated json
out_json = os.path.join(REPORT_DIR, f"family_evaluation_merged_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
with open(out_json, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)

print(f"Saved merged JSON: {os.path.basename(out_json)}")

# Append human-readable summary to latest text report (create new appended copy)
summary_lines = []
summary_lines.append('\n')
summary_lines.append('SECTION: SURROGATE FEATURE IMPORTANCE (RandomForest per LOFO)\n')
summary_lines.append('-'*60 + '\n')
for _, row in df_imp.iterrows():
    fline = f"Held-out: {row['held_out_family']} — Top5: {row['top1']}, {row['top2']}, {row['top3']}, {row['top4']}, {row['top5']}\n"
    summary_lines.append(fline)

new_txt = os.path.join(REPORT_DIR, f"{os.path.splitext(os.path.basename(latest_txt))[0]}_with_importance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
with open(latest_txt, 'r', encoding='utf-8') as f_in, open(new_txt, 'w', encoding='utf-8') as f_out:
    f_out.write(f_in.read())
    f_out.write('\n\n')
    f_out.writelines(summary_lines)

print(f"Saved augmented text report: {os.path.basename(new_txt)}")

# Plot importances: for each family, plot top5 importance values (normalize per family for visibility)
plot_df = pd.DataFrame()
for _, r in df_imp.iterrows():
    fam = r['held_out_family']
    vals = [r['top1_imp'], r['top2_imp'], r['top3_imp'], r['top4_imp'], r['top5_imp']]
    names = [r['top1'], r['top2'], r['top3'], r['top4'], r['top5']]
    temp = pd.DataFrame({'feature': names, 'importance': vals, 'family': fam})
    plot_df = pd.concat([plot_df, temp], ignore_index=True)

plt.figure(figsize=(10,6))
# pivot for stacked view
pivot = plot_df.pivot(index='feature', columns='family', values='importance').fillna(0)
pivot.plot(kind='bar')
plt.title('Top-5 Surrogate Feature Importances per Held-out Family')
plt.ylabel('Importance (avg over sequence positions)')
plt.tight_layout()
plot_path = os.path.join(REPORT_DIR, 'feature_importance_lofo_plot.png')
plt.savefig(plot_path)
plt.close()

print(f"Saved plot: {os.path.basename(plot_path)}")
print('Done')
