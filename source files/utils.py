# utils.py
import requests
from datetime import datetime
from academia.models import News


API_KEY = 'ca2528a12ff24b8bb3bbf8f93c1e72f0'
QUERY = 'Computer Science and Engineering OR Electronic Communication and Engineering'

def fetch_news_articles():
    url = f'https://newsapi.org/v2/everything?q={QUERY}&apiKey={API_KEY}'
    response = requests.get(url)
    data = response.json()

    if data['status'] == 'ok':
        with open("loggin.txt", 'w') as f:
            f.write('Data Received!')
        articles = data['articles']
        for article in articles:
            try:
                title = article['title']
                description = article['description']
                url = article['url']
                source = article['source']['name']
                published_at = datetime.strptime(article['publishedAt'], '%Y-%m-%dT%H:%M:%SZ')
                url_to_image = article['urlToImage'] if 'urlToImage' in article else None

                # Save the article to your database
                news_obj = News(
                    title=title,
                    description=description,
                    url=url,
                    source=source,
                    published_at=published_at,
                    url_to_image=url_to_image
                )
                news_obj.save()
                with open("loggin.txt", 'w') as f:
                    f.write('Saved!')

            except Exception as e:
                print("There is an exception : {e}")


