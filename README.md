# Identity-Protocol
Repository per l'attività progettuale di Sicurezza dell'Informazione M Unibo

# Struttura
Nella repository ci sono due proposte di autenticazione in un server tramite Identity Provider (IDP) e Service Provider (SP).

Dentro alla cartella **demo-flask**, che deriva dalla repository [flask-saml2](https://github.com/mx-moth/flask-saml2) c'è una implementazione con solo python dell'applicativo. (sconsiglio l'utilizzo di questo modulo perché, come scritto sulla repo, non è mantenuto). 
Nella cartella corrente è invece presente una proposta che prevede un IDP fatto in node e un SP in python.

# Testing

Avviare l' Identity Provider con

```node idp.js```


Avviare il Service Provider con

```python3 sp.py```

A questo punto provare a fare il login con credenziali 

**username: asd**

**password: asd**

all' indirizzo http://localhost:5000/login.

In questo modo l'identity provider genererà una risposta che verrà letta come JWT token dal service provider, avviando la sessione all'utente fino al logout. L'utente autenticato potrà navigare nella home page a http://localhost:5000 e potrà fare il logout all' indirizzo http://localhost:5000/logout. Eseguendo il logout la sessione sarà invalidata e per accedere nuovamente si dovrà fare un'altra richiesta all' identity provider.

Il database degli utenti per ora è salvato come mock sull'identity provider.

---

# Link Utili
Flask Login: https://flask-login.readthedocs.io/en/latest/
