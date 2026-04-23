import pytest
import uuid
from unittest.mock import ANY
from src.books.schemas import Book
from datetime import datetime,date

books_prefix = "/api/v1/books"

# verifica ruta care da call la service in primul rand

def test_get_all_books_calls_service(test_client, mock_book_service, mock_session):
    
    # asta trebuie returnat cand get_all_books e called
    # ruta da call la book_service.get_all_books(session) si da serialise la result
    
    mock_book_service.get_all_books.return_value = []

    response = test_client.get(
        books_prefix, 
        headers={"Authorization": "Bearer dummy_token"}
    )

    assert response.status_code == 200 # daca status codeu nu e 200, inseamna ca nimic nu mai conteaza

    mock_book_service.get_all_books.assert_called_once() # da fail daca get_all_books nu a fost niciodata called, si da fail daca a fost called mai mult de 1 data
    
    # asta verifica:
    # 1. daca ruta a fost called doar 1 data
    # 2. called cu exact acel argument
    
    mock_book_service.get_all_books.assert_called_once_with(mock_session)


# verifica daca ruta da return la service_data corect

def test_get_all_books_returns_service_data(test_client, mock_book_service):

    fake_books = [
        Book(
            uid=uuid.UUID("12345678-1234-5678-1234-567812345678"),
            title="Clean Code",
            author="Robert Martin",
            publisher="Prentice Hall",
            published_date=date(2008, 8, 1),
            page_count=431,
            language="English",
            created_at=datetime(2024, 1, 1, 0, 0, 0),
            updated_at=datetime(2024, 1, 1, 0, 0, 0),
        )
    ]

    mock_book_service.get_all_books.return_value = fake_books

    response = test_client.get(books_prefix)

    assert response.status_code == 200
    assert response.json()[0]["title"] == "Clean Code"
    assert response.json()[0]["author"] == "Robert Martin"
    # response.json() da parse la json bodyu fastapi a returnat
    # testu asta verifica daca ruta a dat serialise corect la service return value
    # daca ruta da drop la fielduri sau transforma gresit data -> asta da fail
    #
    # mock_session nu e un parametru aici pentru ca nu il assertam
    # dam request doar la fixturesurile pe care le folosim in test
