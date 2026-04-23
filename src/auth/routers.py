from fastapi import APIRouter, Depends, status, BackgroundTasks
from sqlmodel import JSON
from starlette.status import HTTP_200_OK
from src.celery_tasks import send_email
from .schemas import (
    UserCreateModel,
    UserModel,
    UserLoginModel,
    UserBooksModel,
    EmailModel,
    PaswordResetRequest,
    PasswordResetConfirmModel,
)
from .service import UserService
from src.db.main import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi.exceptions import HTTPException
from .utils import (
    create_acces_token,
    decode_token,
    verify_password,
    create_url_safe_token,
    decode_url_safe_token,
    generate_passwwd_hash
)
from datetime import timedelta, datetime
from fastapi.responses import JSONResponse
from .dependencies import (
    RefreshTokenBearer,
    AccesTokenBearer,
    get_current_user,
    RoleChecker,
)
from src.errors import UserAlreadyExists, UserNotFound, InvalidToken, InvalidCredentials
from src.db.redis import add_jti_to_blocklist
from src.mail import mail, create_message
from src.config import Config

# aici e simplu, doar ia apirouteru si pune nume auth_router
# si user_service e doar clasa de la service, pt shortcut, stii deja

auth_router = APIRouter()
user_service = UserService()
role_checker = RoleChecker(["admin", "user"])

REFRESH_TOKEN_EXPIRY = 2

# /signup e ce se adauga pe langa prefix, status codeu daca tot merge bine, si response_model ce returneaza api u


# aici e simplu, singura diferenta e ca e accesata useer_service din services.py cu await, ca face schimbari la baza de date


@auth_router.post("/send_mail")
async def send_mail(emails: EmailModel):
    emails = (
        emails.addresses
    )  # da extract la lista de email din schema, care e List[str]
    html = "<h1> Welcome to the app </h1>"  # asta e htmlu, bodyu emailului
    subject = "Welcome to our app"
    
    # send_email - functia din celery_tasks
    # .delay() - trimite tasku in redis queue ca sa dea run in background
    # variabilele - necesare ca functia respectiva sa mearga
    
    send_email.delay(emails, subject=subject , body = html) 

    return {"message": "Email sent successfully"}  # returneaza asta daca totu a mers ok


@auth_router.post("/signup", status_code=status.HTTP_201_CREATED)
async def create_user_account(
    payload: UserCreateModel ,session: AsyncSession = Depends(get_session)
):
    email = payload.email

    # asta e checku daca cumva exista emailu, inainte sa creeze contu
    # fara asta, postgresu arunca o eroare de duplicate, pt ca sunt 2 emailuri active, care e o eroare 500
    # cu asta dai return la o eroare 403 clean cu un mesaj bun

    user_exists = await user_service.user_exists(email, session)

    # daca useru exista deja, returneaza 403 forbidden pentru ca nu poti face cont, foarte simplu

    if user_exists:
        raise UserAlreadyExists()

    # aici da la functia din service tot ce are nevoie ca sa creeze useru

    new_user = await user_service.create_user(payload, session)

    # creeaza tokenu URL safe care contine emailu userului
    # asta nu e un JWT, e un itsdangerous token doar pt email
    # returneaza cv de genu: "eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ.abc123"

    token = create_url_safe_token({"email": email})

    # construieste urlu full pe care useru il va accesa in email
    # Config.DOMAIN vine din .env, care e localhost:8000, in productie va fi yoursaas.com
    # {token} la sfarsit e tokenu generat mai devreme, special pt url
    # exemplu: http://localhost:8000/api/v1/auth/verify/eyJlbWFpbCI6I...

    link = f"http://{Config.DOMAIN}/api/v1/auth/verify/{token}"

    # html body u pt email
    # linklu e clickable, si il va duce pe linku de mai sus
    # intro aplicatie reala de productie va fi folosit un template Jinja2 pt a fi totu ok

    html_message = f"""
    <h1>Reset your password </h1>
    <p>Please click this <a href="{link}">link</a> to Reset your password </p>
    """
     
    emails = [email]
    
    subject = "Verify your email"
    
    # send_email - functia din celery_tasks
    # .delay() - trimite tasku in redis queue ca sa dea run in background
    # variabilele - necesare ca functia respectiva sa mearga
    
    send_email.delay(emails, subject=subject , body = html_message)

    return {
        "message": "Account created! Check email to verify your account",
        "user": new_user,
    }


@auth_router.get("/verify/{token}")
async def verify_user_account(token: str, session: AsyncSession = Depends(get_session)):
    token_data = decode_url_safe_token(token)
    
    if 'email' not in token_data.keys():
        raise InvalidCredentials()

    user_email = token_data.get("email")

    if user_email:
        user = await user_service.get_user_by_email(user_email, session)

        if not user:
            raise UserNotFound()

        await user_service.update_user(user, {"is_verified": True}, session)

        return JSONResponse(
            content={"message": "Account verified succesfully"},
            status_code=status.HTTP_200_OK,
        )
    else:
        raise JSONResponse(
            content={"message": "Error occured during verification"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@auth_router.post("/login")
async def login_users(
    payload: UserLoginModel, session: AsyncSession = Depends(get_session)
):

    # aceasta functia doar ia emailu din payload, si parola, iar apoi se pregateste pentru password_hash, care e stocat in db, ca sa compare parolele sa vada daca e valida

    email = payload.email
    password = payload.password
    user = await user_service.get_user_by_email(email, session)

    # aici incepe verificarea, daca asta merge inainte, inseamna ca macar emailul e valid, daca useru e None, inseamna ca nu exista un user cu emailul respectiv, deci si parola e invalida
    if user is not None:

        # here the password by the user is hashed and then compared with the hash stored in the database, if they match, then the password is valid
        # aici parola trimisa de user este hashuita si dupa comparata cu hashul stocat in baza de date, daca se potrives atunci parola e valida

        password_valid = verify_password(password, user.password_has)

        # note: aici nu exista un else care sa zica ca parola e invalida, in schimb daca parola nu e valida, o sa sara peste tot si o sa ajunga la o eroare, lucru care previne un posibil atac de tip brute force deoarece ofera putine informatii

        if password_valid:

            # 2 apeluri la aceasi functie:
            # - tokenul de acces foloseste un expiry default, adica de 1 ora, fara niciun refresh, pentru ca e folosit direct pt a accesa resurse

            acces_token = create_acces_token(
                user_data={
                    "email": user.email,
                    "user_uid": str(user.uid),
                    "role": user.role,
                }
            )

            # - tokenul de refresh foloseste refresh=True si un expiry mai mare, custom
            # - tokenul de refresh este mult mai lung si e folosit doar pentru a face rost de tokenuri de acces noi cand cele vechi expira, niciodata nu atinge resurse direct

            refresh_token = create_acces_token(
                user_data={"email": user.email, "user_uid": str(user.uid)},
                refresh=True,
                expiry=timedelta(days=REFRESH_TOKEN_EXPIRY),
            )

            # jsonresponse e folosit direct in loc de return deoarece:
            # - ofera un control total asupra structurei de response, mai multe fielduri la un nivel mare de customizare, decat daca am folosi un response_model, care e limitat la a returna doar un obiect de un anumit tip, fara fielduri suplimentare sau structuri complexe
            # - un return cu response_model normal ne forta intro schema Pydantic, unde puteam da return doar la un obiect de tip UserModel, dar aici putem returna un obiect mult mai complex, cu fielduri multiple, cum ar fi mesajul, tokenurile, si informatii despre user, toate intr o structura customizata care nu e limitata de schema Pydantic

            return JSONResponse(
                content={
                    "message": "Login successful",
                    "access_token": acces_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "email": user.email,
                        "uid": str(
                            user.uid
                        ),  # uid ul e un uuid, care e un tip de date special, deci trebuie convertit la string inainte sa fie returnat, pentru ca jsonul nu stie sa lucreze cu uuid direct
                    },
                }
            )

    # again: e un mesaj pt amandoua failures, e un security design foarte inteligent anti atacuri

    raise InvalidCredentials()


# functia asta doar genereaza un nou acces token
# token_details e ca user_details din celalat routes, da pe scurt tot ia detaliile tokenului din dependencies.py


@auth_router.get("/refresh_token")
async def get_new_acces_token(token_details: dict = Depends(RefreshTokenBearer())):

    expiry_date = token_details["exp"]  # evident, ia data cand expira

    if datetime.fromtimestamp(expiry_date) > datetime.now():
        new_acces_token = create_acces_token(user_data=token_details["user"])
        return JSONResponse(content={"acces_token": new_acces_token})

    raise InvalidToken()


@auth_router.get("/me", response_model=UserBooksModel)
async def get_current_user(
    user=Depends(get_current_user), _: bool = Depends(role_checker)
):
    return user


@auth_router.get("/logout")
async def revoke_token(token_details: dict = Depends(AccesTokenBearer())):

    jti = token_details["jti"]

    await add_jti_to_blocklist(jti)

    return JSONResponse(
        content={"message": "Logged out succesfully"}, status_code=status.HTTP_200_OK
    )


"""
1. provide the email -> password reset request
2. send password reset link
3. reset password -> password reset confirmation
"""


@auth_router.post("/password-reset-request")
async def password_reset_request(
    email_data: PaswordResetRequest, session: AsyncSession = Depends(get_session)
):
    
    # ia emailu pe care useru trebuie sa il dea la inceput

    email = email_data.email
   
    # creeaza tokenul pt link
    
    token = create_url_safe_token({"email": email})

    # creeaza linku pe care useru va fi redirectionat dupa ce apasa pe butonu de le email
    
    link = f"http://{Config.DOMAIN}/api/v1/auth/password-reset-confirm/{token}"
    
    # asta e html messageu, va fi replaced cu Jinja2 template in viitor probabil
    
    html_message = f"""
    <h1>Reset your password </h1>
    <p>Please click this <a href="{link}">link</a> to Reset your password </p>
    """

    # apeleaza functia facuta de noi ca sa creeze mesaju in sine
    
    message = create_message(
        recipients=[email], subject="Reset your password", body=html_message
    )

    # trimite mesaju real
    
    await mail.send_message(message)
   
    # la asta da return serveru dupa ce trimite emailu
     
    return JSONResponse(
        content={
            "message": "Please check your email for instructions to reset your password"
        },
        status_code=status.HTTP_200_OK,
    )


# useru a dat click pe linku de la email si a landat aici
# trebuie sa dea provide la parola lor noua + confirmarea in request body
# {token} e fix tokenu generat in functia de mai sus, dar il ia in orice caz, ca pe o variabila

@auth_router.post("/password-reset-confirm/{token}")
async def reset_account_password(
    token: str,  # vine din url path
    passwords: PasswordResetConfirmModel, # request modelu, care are 2 fielduri
    session: AsyncSession = Depends(get_session), 
):
    
    # ia cele 2 parole, cea originala si confirmarea
    
    new_password = passwords.new_password
    confirm_password = passwords.confirm_new_password
    
    # daca parolele date nu sunt la fel, ii arunca o eroare
    
    if new_password != confirm_password:
        raise HTTPException(
            detail="The passwords do not match",
            status_code = status.HTTP_400_BAD_REQUEST
        )
    
    # ia token_data din token, adica doar emailu, atat e necesar ca sa faca rost de tot User objectu
    
    token_data = decode_url_safe_token(token)

    # aici ai direct emailu cu .get din token_data 
    
    user_email = token_data.get("email")

    if user_email:
        
        # aici ia user objectu cu ajutoru emailului si dupa verifica daca exista sau nu
        
        user = await user_service.get_user_by_email(user_email, session)

        if not user:
            raise UserNotFound()
        
        # genereaza noul hash pt parola, si da provide la new_password care e parola noua pusa de user
        
        hashed_password = generate_passwwd_hash(new_password)
        
        # asta trimite parola hashuita la user_service.update_user, care e functia speciala pt a updata parola
        
        await user_service.update_user(user, {"password_has": hashed_password}, session)
        
        # daca ajunge aici, totu e ok deci e returnat codu 200 si un mesaj basic
        
        return JSONResponse(
            content={"message": "Password updated succesfully"},
            status_code=status.HTTP_200_OK,
        )
    else:
        
        # aici inseamna ca ceva a mers prost
        
        raise JSONResponse(
            content={"message": "Error occured during updating password"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
