import os
import json
import pandas as pd
import matplotlib.pyplot as plt

# Индивидуальное задание.
# Начальный этап реализации контейнера безопасности для защиты облачного хранилища больших данных.
# Контейнер принимает запросы, проверяет права доступа, блокирует опасные операции,
# формирует журнал событий, выводит результаты в таблице и строит визуализацию.

# Секретные ключи компонентов интеграции.
ACCESS_SYSTEM_KEY = os.getenv('ACCESS_SYSTEM_KEY', 'demo-access-key')
STORAGE_API_KEY = os.getenv('STORAGE_API_KEY', 'demo-storage-key')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', 'demo-admin-token')

# Входные данные.
requests_data = [
    {'user': 'ivanov', 'role': 'reader', 'action': 'read', 'target': 'datasets', 'source': 'api', 'access_key': 'demo-access-key'},
    {'user': 'petrov', 'role': 'reader', 'action': 'write', 'target': 'tables', 'source': 'api', 'access_key': 'demo-access-key'},
    {'user': 'sidorov', 'role': 'editor', 'action': 'write', 'target': 'tables', 'source': 'api', 'access_key': 'demo-access-key'},
    {'user': 'attacker', 'role': 'editor', 'action': 'admin', 'target': 'datasets', 'source': 'api', 'access_key': 'demo-access-key'},
    {'user': 'admin_user', 'role': 'admin', 'action': 'read', 'target': 'service_logs', 'source': 'api', 'access_key': 'demo-access-key'},
    {'user': 'unknown_user', 'role': 'reader', 'action': 'read', 'target': 'datasets', 'source': 'api', 'access_key': 'wrong-key'},
    {'user': 'tarasenko', 'role': 'reader', 'action': 'admin', 'target': 'service_logs', 'source': 'api', 'access_key':'demo-access-key'},
    {'user': 'smichek', 'role': 'editor', 'action': 'read', 'target': 'tables', 'source': 'api', 'access_key':'demo_access_key'},
    {'user': 'markin', 'role': 'editor', 'action': 'write', 'target': 'tables', 'source': 'api', 'access_key':'wrong-key'}
]

# Политики доступа.
ROLE_RULES = {
    'reader': {
        'datasets': ['read'],
        'tables': ['read'],
        'service_logs': []
    },
    'editor': {
        'datasets': ['read', 'write'],
        'tables': ['read', 'write'],
        'service_logs': []
    },
    'admin': {
        'datasets': ['read', 'write', 'admin'],
        'tables': ['read', 'write', 'admin'],
        'service_logs': ['read']
    }
}

# Опасные комбинации роли и действия.
DANGEROUS_ACTIONS = {
    ('reader', 'write'),
    ('reader', 'admin'),
    ('editor', 'admin')
}

# Контейнер расчета.
results_lst = []
audit_lst = []
allowed_count = 0
blocked_count = 0

for req in requests_data:
    user = req['user']
    role = req['role']
    action = req['action']
    target = req['target']
    source = req['source']
    access_key = req['access_key']

    decision = 'blocked'
    reason = 'Неизвестная причина'

    if access_key != ACCESS_SYSTEM_KEY:
        reason = 'Неверный ключ интеграции'
    elif role not in ROLE_RULES:
        reason = 'Неизвестная роль'
    elif target not in ROLE_RULES[role]:
        reason = 'Неизвестный объект доступа'
    elif (role, action) in DANGEROUS_ACTIONS:
        reason = 'Опасная операция по политике безопасности'
    elif action not in ROLE_RULES[role][target]:
        reason = 'Недостаточно прав для выполнения операции'
    else:
        decision = 'allowed'
        reason = 'Запрос соответствует политике доступа'

    if decision == 'allowed':
        allowed_count += 1
    else:
        blocked_count += 1

    result = {
        'user': user,
        'role': role,
        'action': action,
        'target': target,
        'source': source,
        'decision': decision,
        'reason': reason
    }

    results_lst.append(result)
    audit_lst.append(
        'user=' + str(user) +
        ' role=' + str(role) +
        ' action=' + str(action) +
        ' target=' + str(target) +
        ' source=' + str(source) +
        ' decision=' + str(decision) +
        ' reason=' + str(reason)
    )

# Сохранение результатов в json.
with open('results.json', 'w', encoding='utf-8') as f:
    json.dump({'results': results_lst}, f, ensure_ascii=False, indent=2)

# Сохранение журнала событий.
with open('audit.log', 'w', encoding='utf-8') as f:
    for line in audit_lst:
        f.write(line + '\n')

print('results_lst: ', results_lst)
print('audit_lst: ', audit_lst)

# Табличное представление результатов.
N = range(1, len(results_lst) + 1)
table1 = []
for i in range(len(results_lst)):
    table1.append((
        i + 1,
        results_lst[i]['user'],
        results_lst[i]['role'],
        results_lst[i]['action'],
        results_lst[i]['target'],
        results_lst[i]['decision']
    ))

tframe = pd.DataFrame(table1, columns=['N', 'user', 'role', 'action', 'target', 'decision'])
print(tframe)

# Дополнительная таблица со сводкой.
summary_table = [
    ('Разрешено', allowed_count),
    ('Заблокировано', blocked_count)
]
tframe2 = pd.DataFrame(summary_table, columns=['result', 'count'])
print(tframe2)

# Контейнер визуализации.
plt.figure()
plt.bar(tframe2['result'], tframe2['count'])
plt.title('Результаты работы контейнера безопасности')
plt.xlabel('Решение контейнера')
plt.ylabel('Количество запросов')
plt.savefig('chart1.png')
plt.close()

# Круговая диаграмма.
vals = [allowed_count, blocked_count]
labels = ['Разрешено', 'Заблокировано']
explode = (0.1, 0.1)
fig, ax = plt.subplots()
ax.pie(
    vals,
    explode=explode,
    labels=labels,
    autopct='%1.1f%%',
    shadow=True,
    wedgeprops={'lw': 1, 'ls': '--', 'edgecolor': 'k'}
)
ax.axis('equal')
plt.savefig('chart2.png')
plt.close()

# Гистограмма по пользователям.
users_lst = []
blocked_by_user_lst = []

for req in results_lst:
    if req['decision'] == 'blocked':
        if req['user'] not in users_lst:
            users_lst.append(req['user'])

for user in users_lst:
    count_blocked = 0
    for req in results_lst:
        if req['user'] == user and req['decision'] == 'blocked':
            count_blocked += 1
    blocked_by_user_lst.append(count_blocked)

if len(users_lst) > 0:
    tfame = pd.DataFrame(list(zip(users_lst, blocked_by_user_lst)), columns=['user', 'blocked_count'])
    plt.figure()
    plt.bar(tfame['user'], tfame['blocked_count'])
    plt.title('Количество заблокированных запросов по пользователям')
    plt.xlabel('Пользователь')
    plt.ylabel('Количество блокировок')
    plt.xticks(rotation=15)
    plt.savefig('chart3.png')
    plt.close()

print('Файлы results.json, audit.log, chart1.png, chart2.png, chart3.png успешно созданы.')