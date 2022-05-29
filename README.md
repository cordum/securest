= Taco Cloud

There are three projects in this folder:

 - tacocloud : This is the same Taco Cloud project,
   altered to act as an OAuth2 resource server.
 - auth-server : An OAuth2 authorization server based on Spring Authorization
   Server (https://github.com/spring-projects-experimental/spring-authorization-server).
 - tacocloud-admin : An admin client to consume the API exposed by tacocloud,
   using tokens obtained from the auth-server.

Then, you can manually interact with the authorization server by TODO:FINISH THIS

http://localhost:9000/oauth2/authorize?response_type=code&client_id=taco-admin-client&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/taco-admin-client&scope=writeIngredients+deleteIngredients
