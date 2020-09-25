#### Прототип OIDC аутентификации в CMJ на примере Keycloak.
1. Установите и запустите Keycloak. Он должен слушать порт 8080 (по умолчанию).
2. Импортируйте в Keycloak реалм из файла `demo-realm.json`
3. Запустите данное приложение

    `java -jar oidc-cmj-web.jar`    
4. Откройте в браузере http://localhost:8081/oidc-cmj-web/index.html
5. Логин: `user`. Пароль: `password` - авторизованный пользователь
   Логин: `z1`. Пароль: `1` - не авторизованный пользователь
   
#### Если Keycloak не на localhost:8080
1. Измените параметры подключения в `src\main\webapp\keycloak.json`, `src\main\resources\server.properties` и `src\main\webapp\index.html`
2. Пересоберите проект 

    `mvn package`
 