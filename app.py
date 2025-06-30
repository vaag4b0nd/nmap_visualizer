from flask import Flask, render_template, request, jsonify
import xml.etree.ElementTree as ET
import os
import requests
import re
import urllib.parse
import markdown  # Для преобразования Markdown в HTML
from packaging import version as pkg_version

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit
app.config['OPENAI_API_KEY'] = 'YOUR_KEY'  # Замените на реальный ключ

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def parse_nmap_xml(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        hosts = []
        port_stats = {}
        
        for host in root.findall('host'):
            address = host.find('address')
            if address is None:
                continue
                
            ip = address.get('addr')
            hostname_elem = host.find('hostnames/hostname')
            hostname = hostname_elem.get('name') if hostname_elem is not None else "N/A"
            
            # Получаем информацию об ОС
            os_info = "Unknown"
            osmatch = host.find('.//osmatch')
            if osmatch is not None:
                os_info = f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)"
            
            # Получаем uptime
            uptime = host.find('.//uptime')
            uptime_info = uptime.get('seconds') + "s" if uptime is not None else "N/A"
            
            ports = []
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else "unknown"
                product = service_elem.get('product') if service_elem is not None else ""
                version = service_elem.get('version') if service_elem is not None else ""
                extra_info = service_elem.get('extrainfo') if service_elem is not None else ""
                cpe = service_elem.get('cpe') if service_elem is not None else ""
                
                # Извлекаем чистую версию
                clean_version = None
                if version:
                    # Удаляем неалфавитные префиксы/суффиксы
                    match = re.search(r'(\d+[\.\d]+\d)', version)
                    if match:
                        clean_version = match.group(1)
                
                ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'product': product,
                    'version': clean_version if clean_version else version,
                    'extra_info': extra_info,
                    'cpe': cpe
                })
                
                if state == 'open':
                    key = f"{port_id}/{service}"
                    port_stats[key] = port_stats.get(key, 0) + 1
            
            if any(p['state'] == 'open' for p in ports):
                hosts.append({
                    'ip': ip,
                    'hostname': hostname,
                    'os': os_info,
                    'uptime': uptime_info,
                    'ports': ports
                })
        
        sorted_stats = sorted(port_stats.items(), key=lambda x: x[1], reverse=True)
        return hosts, sorted_stats
    except Exception as e:
        print(f"Ошибка парсинга XML: {e}")
        return [], []

def get_ai_recommendations(host_data):
    """Получаем рекомендации от ИИ для пентеста и возвращаем в формате HTML"""
    if not app.config['OPENAI_API_KEY'] or app.config['OPENAI_API_KEY'] == 'your-openai-api-key':
        return "<p>⚠️ Введите ваш OpenAI API ключ в app.py</p>"

    # Формируем детальный промпт для ИИ
    prompt = f"""
    Ты опытный пентестер и специалист по кибербезопасности.
    Проанализируй результаты сканирования NMAP и предоставь детальные рекомендации.

    Хост: {host_data['ip']} ({host_data['hostname']})
    Операционная система: {host_data['os']}
    Время работы: {host_data['uptime']}

    Детали открытых портов и сервисов:
    """

    for port in host_data['ports']:
        if port['state'] == 'open':
            prompt += f"\n- Порт {port['port']}/{port['protocol']}: {port['service']}"
            if port['product']:
                prompt += f" ({port['product']}"
                if port['version']:
                    prompt += f" версия {port['version']}"
                prompt += ")"
            if port['cpe']:
                prompt += f"\n  CPE: {port['cpe']}"
            if port['extra_info']:
                prompt += f"\n  Доп. информация: {port['extra_info']}"

    prompt += """

    Для каждого сервиса:
    1. Дай формально-техническое описание сервиса, его назначение и типичное использование
    2. Перечисли известные уязвимости для данной версии ПО (если версия указана)
    3. Предложи конкретные техники эксплуатации (с примерами команд и инструментов)
    4. Укажи рекомендации по защите и харденингу

    Дополнительно:
    - Предложи общие рекомендации по тестированию безопасности хоста
    - Опиши методы повышения безопасности ОС
    - Перечисли потенциальные векторы атаки на основе всех данных
    - Упомяни известные эксплоиты и CVE для выявленных сервисов

    Ответ должен быть структурированным, технически точным и содержательным.
    Используй профессиональную терминологию и формальный стиль изложения.
    Выведи ответ в формате Markdown с четким разделением на разделы.
    """

    try:
        headers = {
            "Authorization": f"Bearer {app.config['OPENAI_API_KEY']}",
            "Content-Type": "application/json"
        }

        data = {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=45  # Увеличиваем таймаут для детального анализа
        )

        if response.status_code == 200:
            result = response.json()
            markdown_content = result['choices'][0]['message']['content']
            # Конвертируем Markdown в HTML
            html_content = markdown.markdown(markdown_content)
            return html_content
        else:
            return f"<p>Ошибка API: {response.status_code} - {response.text}</p>"

    except Exception as e:
        return f"<p>Ошибка: {str(e)}</p>"

def normalize_version(version_str):
    """Нормализует версию для сравнения"""
    try:
        # Удаляем нечисловые префиксы/суффиксы
        clean_version = re.sub(r'[^0-9.]', '', version_str)
        return pkg_version.parse(clean_version)
    except:
        return None

def is_version_affected(cve_version, product_version):
    """Проверяет, затронута ли версия уязвимостью"""
    try:
        # Нормализуем версии для сравнения
        cve_ver = normalize_version(cve_version)
        product_ver = normalize_version(product_version)
        
        if not cve_ver or not product_ver:
            return False
            
        # Проверяем вхождение в диапазон (если указан)
        if "to" in cve_version.lower():
            parts = re.split(r'\s*to\s*', cve_version, flags=re.IGNORECASE)
            if len(parts) == 2:
                start_ver = normalize_version(parts[0])
                end_ver = normalize_version(parts[1])
                if start_ver and end_ver:
                    return start_ver <= product_ver <= end_ver
        # Проверка "and earlier"
        elif "and earlier" in cve_version.lower():
            base_ver = normalize_version(cve_version.replace("and earlier", "").strip())
            return product_ver <= base_ver if base_ver else False
        # Точечная версия
        else:
            return product_ver == cve_ver
            
    except Exception as e:
        print(f"Ошибка сравнения версий: {e}")
    return False

def get_cve_for_product(product, version):
    """Поиск CVE для продукта и версии с улучшенной обработкой"""
    if not product:
        return []
    
    try:
        # Упрощаем запрос: используем только ключевые слова
        keywords = re.findall(r'[a-z]{3,}', product, re.IGNORECASE)
        if not keywords:
            return []
        
        # Формируем поисковый запрос из ключевых слов
        query = " ".join(keywords[:3])  # Берем не более 3 ключевых слов
        encoded_query = urllib.parse.quote(query)
        
        # Используем новый API NVD (v2)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}"
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            
            for item in data.get('vulnerabilities', []):
                cve_data = item['cve']
                cve_id = cve_data['id']
                
                # Описание на английском
                description = next(
                    (desc['value'] for desc in cve_data['descriptions'] if desc['lang'] == 'en'),
                    "No description available"
                )
                
                # Получаем CVSS v3 оценку
                cvss_v3 = "N/A"
                if 'metrics' in cve_data and 'cvssMetricV31' in cve_data['metrics']:
                    cvss_v3 = cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'metrics' in cve_data and 'cvssMetricV30' in cve_data['metrics']:
                    cvss_v3 = cve_data['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                elif 'metrics' in cve_data and 'cvssMetricV2' in cve_data['metrics']:
                    cvss_v3 = cve_data['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                
                # Проверяем совпадение версии
                version_match = True
                affected_versions = []
                
                if version:
                    # Ищем упоминания версий в описании
                    version_pattern = re.compile(r'\b(\d+[\.\d]+[\w]*)\b', re.IGNORECASE)
                    found_versions = set(version_pattern.findall(description))
                    
                    # Проверяем каждую найденную версию
                    version_match = False
                    for v in found_versions:
                        if is_version_affected(v, version):
                            affected_versions.append(v)
                            version_match = True
                
                if version_match:
                    cves.append({
                        'id': cve_id,
                        'description': description,
                        'cvss': cvss_v3,
                        'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        'affected_versions': affected_versions
                    })
            
            # Сортируем по CVSS (высокие оценки первыми)
            return sorted(
                cves, 
                key=lambda x: float(x['cvss']) if x['cvss'] != "N/A" else 0, 
                reverse=True
            )[:50]  # Ограничиваем 50 результатами
        else:
            print(f"Ошибка NVD API: {response.status_code} - {response.text}")
            return []
    
    except Exception as e:
        print(f"Ошибка при получении CVE: {e}")
        return []

@app.route('/', methods=['GET', 'POST'])
def index():
    hosts = []
    port_stats = []
    filename = None
    
    if request.method == 'POST':
        file = request.files['xml_file']
        if file and file.filename.endswith('.xml'):
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filename)
            hosts, port_stats = parse_nmap_xml(filename)
    
    return render_template('index.html', 
                           hosts=hosts, 
                           port_stats=port_stats,
                           filename=filename)

@app.route('/get_ai_recommendations', methods=['POST'])
def ai_recommendations():
    host_data = request.json
    recommendations = get_ai_recommendations(host_data)
    return jsonify({'html': recommendations})

@app.route('/get_cves', methods=['POST'])
def cves():
    data = request.json
    return jsonify(get_cve_for_product(data['product'], data['version']))

@app.route('/search_cve', methods=['POST'])
def search_cve():
    """Новый endpoint для поиска CVE по произвольному запросу"""
    data = request.json
    product = data.get('product', '')
    version = data.get('version', '')
    cves = get_cve_for_product(product, version)
    return jsonify(cves)

if __name__ == '__main__':
    app.run(debug=True)
