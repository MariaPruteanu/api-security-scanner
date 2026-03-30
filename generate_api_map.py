import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os

os.makedirs('figures', exist_ok=True)

fig, ax = plt.subplots(figsize=(14, 10))
ax.set_xlim(0, 14)
ax.set_ylim(0, 10)
ax.axis('off')

# Центр
ax.text(7, 5, '🔍\nAPI\nScanner', ha='center', va='center', 
        fontsize=20, fontweight='bold', color='#2c3e50')

# API вокруг центра
apis = [
    (7, 8.5, 'Petstore API\n(20 endpoints)', '#2ecc71', '🐕'),
    (11, 6, 'JSONPlaceholder\n(6 endpoints)', '#3498db', '📄'),
    (10, 2, 'Reqres.in\n(8 endpoints)', '#e74c3c', '👤'),
    (3, 2, 'GitHub API\n(25 endpoints)', '#f39c12', '🐙'),
    (2, 6, 'Fake Store API\n(12 endpoints)', '#9b59b6', '🛒'),
]

for x, y, label, color, icon in apis:
    # Используем FancyBboxPatch вместо Rectangle для boxstyle
    rect = mpatches.FancyBboxPatch(
        (x-1.8, y-0.7), 3.6, 1.4,
        boxstyle="round,pad=0.3",
        linewidth=2, 
        edgecolor='black', 
        facecolor=color, 
        alpha=0.8
    )
    ax.add_patch(rect)
    
    # Иконка
    ax.text(x, y+0.25, icon, ha='center', va='center', fontsize=18)
    
    # Текст
    ax.text(x, y-0.25, label, ha='center', va='center', 
            fontsize=10, fontweight='bold', color='white')
    
    # Стрелки от центра
    ax.annotate('', xy=(x, y), xytext=(7, 5),
                arrowprops=dict(arrowstyle='->', linewidth=2, 
                               color=color, alpha=0.7))

ax.set_title('Рисунок 5.1 — Карта тестируемых открытых API', 
             fontsize=14, fontweight='bold', pad=20)

plt.savefig('figures/figure_5_1_api_map.png', dpi=300, bbox_inches='tight')
plt.show()
print("✅ Рисунок 5.1 сохранён в figures/figure_5_1_api_map.png")
