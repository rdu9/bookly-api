import pytest
from unittest.mock import patch, MagicMock
from src.auth.schemas import UserCreateModel
import uuid

auth_prefix = "/api/v1/auth"

# - un dictionar valabil pe tot fisieru
# - definit odata sus de tot si refolosit la toate testele
# - un change aici da update la toate testele sincron

valid_signup_data = {
    "username": "jdoe",
    "email": "jdoe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "password": "S3cur3P@ssword!",
}

# testam cazul bun


def test_signup_returns_201_when_user_does_not_exist(
    test_client, mock_user_service, mock_session
):

    # controlam ce user_exists returenaza: False ( emailu nu e luat )
    # ruta citeste valoarea asta si decide daca sa continue sau nu cu creearea

    mock_user_service.user_exists.return_value = False

    # ruta asta returneaza created_user in response bodyu de mai jos, deci dam mock ului un return value realistic ca sa fie serializat

    mock_user_service.create_user.return_value = {
        "uid": "new-uid-xyz",
        **valid_signup_data,
    }
    with patch("src.auth.routers.send_email") as mock_send_email:
        response = test_client.post(f"{auth_prefix}/signup", json=valid_signup_data)

        assert response.status_code == 201

        # vede daca ruta a verificat emailu si a dat sesiunea

        mock_user_service.user_exists.assert_called_once_with(
            valid_signup_data["email"], mock_session
        )

        # UserCreateModel(**valid_signup_data) creeaza pydantic modelu
        # ruta da recieve la json body si creeaza obiectu internal
        # creem acelasi model aici ca sa vedem daca ruta ia dat pass corect

        expected_user_data = UserCreateModel(**valid_signup_data)
        mock_user_service.create_user.assert_called_once_with(
            expected_user_data, mock_session
        )
        mock_send_email.delay.assert_called_once()


# testam cazu cand emailu inca exista


def test_signup_returns_403_when_user_already_exists(
    test_client, mock_user_service, mock_session
):

    # user_exists returneaza True deci emailu deja exista
    # ruta ar trebui sa dea raise la UserAlreadyExists

    mock_user_service.user_exists.return_value = True

    response = test_client.post(f"{auth_prefix}/signup", json=valid_signup_data)

    assert response.status_code in (
        403,
        409,
    )  # accepta ori 403 ori 409, amandoua sunt valide

    # daca useru deja exista, create_user n ar trebui sa fie niciodata called
    # assert_not_called() e cel mai important lucru, daca da fail inseamna ca methodu a fost called

    mock_user_service.create_user.assert_not_called()


# testam cazu cand payloadu e invalid


@pytest.mark.parametrize(
    "bad_payload, missing_field",
    [
        (
            {k: v for k, v in valid_signup_data.items() if k != "email"},
            "email",
        ),  # primu caz pt cele 2 variabile
        (
            {k: v for k, v in valid_signup_data.items() if k != "password"},
            "password",
        ),  # al doilea caz pt cele 2 variabile
    ],
)
def test_signup_returns_422_on_missing_required_fields(
    test_client, mock_user_service, bad_payload, missing_field
):
    # mark.parametrize pe scurt scoate emailu prima oara, si dupa parola, sa vada daca totu e handled cum trb

    response = test_client.post(f"{auth_prefix}/signup", json=bad_payload)

    assert (
        response.status_code == 422
    )  # asta verifica daca eroarea a fost handled cum trebuie

    mock_user_service.user_exists.assert_not_called()
    mock_user_service.create_user.assert_not_called()
    # serviceu n ar trebui sa fie niciodata atins daca e o eroare de payload din prima, si asta verifica daca sa intamplat sau nu


def test_login_when_user_doesnt_exist(test_client, mock_session, mock_user_service):

    mock_user_service.get_user_by_email.return_value = None

    json_login = {"email": "pula200@gmail.com", "password": "dacoaie"}

    response = test_client.post(f"{auth_prefix}/login", json=json_login)

    assert response.status_code == 401

    mock_user_service.get_user_by_email.assert_called_once_with(
        json_login["email"], mock_session
    )


@pytest.mark.asyncio
async def test_login_when_user_exists_with_valid_credentials(
    test_client, mock_session, mock_user_service
):

    # simulam un user valid returnat din db
    mock_user = MagicMock()
    mock_user.email = "pula200@gmail.com"
    mock_user.uid = uuid.uuid4()
    mock_user.role = "user"
    mock_user.password_has = "hashed_password"

    mock_user_service.get_user_by_email.return_value = mock_user

    json_login = {"email": "pula200@gmail.com", "password": "dacoaie"}

    with patch("src.auth.routers.verify_password", return_value=True), patch("src.auth.routers.create_acces_token",side_effect=["mock_access_token", "mock_refresh_token"],
    ):
        response = test_client.post(f"{auth_prefix}/login", json=json_login)

    assert response.status_code == 200

    response_body = response.json()

    # verificam ca tokenurile exista in response
    assert "access_token" in response_body
    assert "refresh_token" in response_body
    assert "message" in response_body
    assert response_body["message"] == "Login successful"

    # verificam ca userul din response are datele corecte
    assert response_body["user"]["email"] == mock_user.email
    assert response_body["user"]["uid"] == str(mock_user.uid)

    # verificam ca get_user_by_email a fost chemat cu emailul corect
    mock_user_service.get_user_by_email.assert_called_once_with(
        json_login["email"], mock_session
    )

# negative path 1

@pytest.mark.asyncio
async def test_verify_user_account_negative_path_1(test_client,mock_session,mock_user_service):
    
    decode_url_dict = {"email_error": "emailtest@gmail.com"}
    
    with patch("src.auth.routers.decode_url_safe_token", return_value= decode_url_dict):
        
        response = test_client.get(f"{auth_prefix}/verify/random_string")
        
        assert response.status_code == 401
    
# negative path 2

@pytest.mark.asyncio
async def test_verify_user_account_negative_path_2(test_client,mock_session,mock_user_service):
    
    mock_user_service.get_user_by_email.return_value = None
    
    decode_url_dict = {"email": "emailtest@gmail.com"}
    
    with patch("src.auth.routers.decode_url_safe_token", return_value=decode_url_dict):
        
       response = test_client.get(f"{auth_prefix}/verify/random_string")
        
       assert response.status_code == 404

# happy path

@pytest.mark.asyncio
async def test_verify_user_account_happy_path(test_client,mock_session,mock_user_service):

    mock_user = MagicMock()
    mock_user.email = "emailtest@gmail.com"
    mock_user.uid = uuid.uuid4()
    mock_user.role = "user"
    mock_user.password_has = "hashed_password"
    
    mock_user_service.get_user_by_email.return_value = mock_user
    mock_user_service.update_user.return_value = mock_user
    
    decode_url_dict = {"email": "emailtest@gmail.com"}
    
    with patch("src.auth.routers.decode_url_safe_token", return_value = decode_url_dict):
        
        response = test_client.get(f"{auth_prefix}/verify/random_string")
        
        assert response.status_code == 200
        
        response_body = response.json()
        
        assert "message" in response_body
        assert response_body["message"] == "Account verified succesfully"
        
        mock_user_service.get_user_by_email.assert_called_once_with(decode_url_dict.get("email"), mock_session)
        
        