Simple Example
==============

This is a simple application demonstrating how to use Flask-Tokens to protect a resource.

To try it out, install Flask-Tokens, then run `app.py`, and use your favorite REST client to send a few requests:

*   **GET:** `/`
    
    Should say "Hi, anonymous!"  

*   **POST:** `/auth`  
    **Form:** `username=testuser&password=test123`
    
    This will give you a long token string; copypaste this

*   **GET:** `/`  
    **Header:** `Authorization: Bearer <your token goes here>`
    
    Should now say "Hi, testuser!"

You can also try sending requests to `/protected` - with no authorization, it will give you a `403 Forbidden` response.
