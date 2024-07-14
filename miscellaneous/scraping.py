from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
app = Flask(__name__)

# Define headers if needed (e.g., User-Agent)
headers = {
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

def count_vacancies(vacancy_page_url):
    try:
        response = requests.get(vacancy_page_url, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        return 0, str(e)
    soup = BeautifulSoup(response.content, 'html.parser')
    # Debug: Print the soup content (HTML)
    html_content = soup.prettify()[:10000] # Printing first 10000 characters for better inspection
    print("HTML Content:", html_content)
    # Print out some tags to help identify patterns
    tags = soup.find_all(['li', 'div'])
    for tag in tags[:50]:
        print("Tag:", tag)
        print("Class:", tag.get('class'))

    # Expanded regex pattern for real estate vacancies
    pattern = re.compile(
    'vacancy|listing|available|property|unit|apartment|home|house|condo|rent|lease|real estate|housing|residence|'
    'flat|suite|dwelling|tenancy|rental|accommodation|lodging|sublet|living space|room|quarters|vacant|open house|showing|viewing|model home|for sale|for rent|for lease',
    re.IGNORECASE
    )
    vacancies = []
    for tag in tags:
        if tag.get('class') and pattern.search(' '.join(tag.get('class'))):
            vacancies.append(tag)
    # Debug: Print found elements
    print("Found elements:", vacancies)
    return len(vacancies), None


@app.route('/get_vacancy_count', methods=['POST'])
def get_vacancy_count():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    vacancy_count, error = count_vacancies(url)
    if error:
        return jsonify({'error': error}), 400
    return jsonify({'vacancy_count': vacancy_count})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
