from celery import shared_task
from academia.utils import fetch_news_articles

@shared_task
def fetch_news_articles_task():
    with open("loggin.txt", 'w') as f:
        f.write('Here!')
    fetch_news_articles()