# Identity-Protocol
Repository per l'attività progettuale di Sicurezza dell'Informazione M Unibo

# Testing

Avviare l' Identity Provider con

``` node idp.js```


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
