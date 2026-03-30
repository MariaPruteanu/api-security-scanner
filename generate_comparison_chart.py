import matplotlib.pyplot as plt
import os

os.makedirs('figures', exist_ok=True)

scanners = ['Разработанный\nсканер', 'OWASP ZAP', 'Nuclei', 'Burp Suite\nCommunity']
efficiency = [89, 41, 58, 63]
colors = ['#2ecc71', '#3498db', '#e67e22', '#9b59b6']

fig, ax = plt.subplots(figsize=(12, 7))
bars = ax.bar(scanners, efficiency, color=colors, edgecolor='black', linewidth=1.5)

for bar, eff in zip(bars, efficiency):
    height = bar.get_height()
    ax.annotate(f'{eff}%', 
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), 
                textcoords="offset points",
                ha='center', va='bottom', 
                fontsize=13, fontweight='bold')

ax.set_ylabel('Общая эффективность (%)', fontsize=13)
ax.set_title('Рисунок 5.7 — Сравнение эффективности обнаружения уязвимостей', 
             fontsize=14, fontweight='bold', pad=20)
ax.set_ylim(0, 100)
ax.grid(True, alpha=0.3, axis='y', linestyle='--')

plt.savefig('figures/figure_5_7_scanner_comparison.png', dpi=300, bbox_inches='tight')
plt.show()
print("✅ Рисунок 5.7 сохранён в figures/figure_5_7_scanner_comparison.png")
