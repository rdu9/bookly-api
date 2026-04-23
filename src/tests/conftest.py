import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from src import app
from src.db.main import get_session
from src.auth.dependencies import AccesTokenBearer, RefreshTokenBearer, RoleChecker
from src.books.routes import acces_token_bearer, role_checker
from src.auth.routers import role_checker as auth_role_checker

# auth_class instances - folosite ca chei pt dependency_overrides
# astea trebuie sa fie aceleasi obiecte ca aplicatia deja creeata
# fastapi da match la dependencieuri cu identitatea obiectului - instance gresit = niciun override

# acces_token_bearer - importat din books/routes.py unde e instantiat
# role_checker - importat din books/routes.py unde e instantiat
# auth_role_checker - importat din auth/routers.py, diferit obiect de cel din books


@pytest.fixture()
def mock_session() -> AsyncMock:
    return AsyncMock()


@pytest.fixture()
def mock_user_service() -> AsyncMock:
    return AsyncMock()


@pytest.fixture()
def mock_book_service() -> AsyncMock:
    return AsyncMock()


# autouse = True - acest fixture da run automat pentru fiecare test, deci nu trebuie folosit ca parametru
# foloseste mock_session , mock_user_service , mock_book_service ca paramtetrii
# da register la toate dependency overrides cu aplicatia:
# - get_session -> da yield la mock session
# - acces_token_bearer -> bypassed ( fara jwt validation in teste )
# - role_checker -> bypassed ( fara 403 blocking tests )
#
# yield - generator fixtureu
# - totu inainte de yield = setup ( da run inainte de test )
# - yield = testu da run aici
# - totu dupa yield = teardown ( da run dupa test )
#
# app.dependency_overrides.clear() da remove la toate overrideurile dupa fiecare text, ca sa nu existe probleme


@pytest.fixture(autouse=True)
def apply_dependency_overrides(mock_session, mock_user_service, mock_book_service):

    async def get_session_override():
        yield mock_session
        # asta e un async generator - acelasi shape ca realu get_session
        # fastapi da call la asta si primeste mock_session ca dependencyu injectat

    app.dependency_overrides[get_session] = get_session_override
    app.dependency_overrides[acces_token_bearer] = lambda: MagicMock()
    app.dependency_overrides[auth_role_checker] = lambda: MagicMock()
    app.dependency_overrides[role_checker] = lambda: MagicMock()

    with patch("src.db.redis.token_blocklist", AsyncMock()), patch("src.auth.routers.user_service", mock_user_service), patch("src.books.routes.book_service", mock_book_service):
        yield

    # testu da run aici

    app.dependency_overrides.clear()  # cleanup dupa fiecare test


# foloseste testclient ca un context manager
# raise_server_exceptions = True inseamna ca daca aplicatia da raise la o exceptie unhandled, testu il vede ca o exceptie reala nu ca pe un 500 response


@pytest.fixture()
def test_client() -> TestClient:
    # seteaza base_url ca sa mearga aplicatia
    with TestClient(app, base_url="http://localhost") as client:
        yield client