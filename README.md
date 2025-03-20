# Keycloak SSO для Pimcore

Этот бандл предоставляет интеграцию между административным интерфейсом Pimcore и Keycloak SSO.

## Возможности

- Аутентификация в административном интерфейсе Pimcore через Keycloak SSO
- Автоматическое создание пользователей Pimcore на основе данных из Keycloak
- Синхронизация данных пользователя при каждом логине
- Поддержка Single Logout (выход одновременно из Pimcore и Keycloak)
- Соответствие ролей Keycloak и Pimcore

## Требования

- Pimcore 11
- Symfony 6.4
- PHP 8.1 или выше
- Работающий сервер Keycloak

## Установка

1. **Установите бандл через Composer**

```bash
composer require iperson1337/pimcore-keycloak-bundle
```

2. **Включите бандл в `config/bundles.php`**

```php
return [
    // ...
    Iperson1337\PimcoreKeycloakBundle\PimcoreKeycloakBundle::class => ['all' => true],
    // ...
];
```

3. **Создайте файл конфигурации `config/packages/iperson1337_pimcore_keycloak.yaml`**

```yaml
iperson1337_pimcore_keycloak:
    default_target_route_name: 'pimcore_admin_index'
    admin_user_class: 'Pimcore\Model\User'

    # Автоматически создавать пользователей в Pimcore при первом входе через Keycloak
    auto_create_users: true

    # Синхронизировать данные пользователя при каждом входе
    sync_user_data: true

    # Настройки подключения к Keycloak
    keycloak:
        client_id: '%env(KEYCLOAK_CLIENT_ID)%'
        client_secret: '%env(KEYCLOAK_CLIENT_SECRET)%'
        server_url: '%env(KEYCLOAK_SERVER_BASE_URL)%'
        server_public_url: '%env(KEYCLOAK_SERVER_PUBLIC_BASE_URL)%'
        server_private_url: '%env(KEYCLOAK_SERVER_PRIVATE_BASE_URL)%'
        realm: '%env(KEYCLOAK_REALM)%'
        ssl_verification: true # Рекомендуется всегда использовать true в production

    # Маппинг полей пользователя Keycloak на поля пользователя Pimcore
    user_mapping:
        username: 'preferred_username'
        email: 'email'
        firstname: 'given_name'
        lastname: 'family_name'
```

4. **Добавьте переменные окружения в `.env` файл**

```
###> iperson1337/pimcore-keycloak-bundle ###
KEYCLOAK_CLIENT_ID=pimcore-admin
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_SERVER_BASE_URL=https://keycloak.example.com/auth
KEYCLOAK_SERVER_PUBLIC_BASE_URL=https://keycloak.example.com/auth
KEYCLOAK_SERVER_PRIVATE_BASE_URL=https://keycloak.example.com/auth
KEYCLOAK_REALM=your-realm
###< iperson1337/pimcore-keycloak-bundle ###
```

5. **Настройте security.yaml**

```yaml
# config/packages/security.yaml
security:
    enable_authenticator_manager: true

    providers:
        # Стандартный провайдер Pimcore
        pimcore_admin:
            id: Pimcore\Security\User\UserProvider

    firewalls:
        # Общедоступные ресурсы, не требующие аутентификации
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        # Публичные API, не требующие аутентификации
        public_api:
            pattern: ^/api/public
            security: false

        #pimcore_admin: '%pimcore_admin_bundle.firewall_settings%'

        # Pimcore Admin интерфейс с аутентификацией через Keycloak
        pimcore_admin:
            pattern: ^/admin
            provider: pimcore_admin
            custom_authenticators:
                - Pimcore\Bundle\AdminBundle\Security\Authenticator\AdminTokenAuthenticator
                - Iperson1337\PimcoreKeycloakBundle\Security\Authenticator\KeycloakAuthenticator
            form_login:
                login_path: pimcore_admin_login
                check_path: pimcore_admin_login_check
                default_target_path: pimcore_admin_index
                username_parameter: username
                password_parameter: password
            logout:
                path: pimcore_admin_logout
                target: pimcore_admin_login
            entry_point: form_login

    access_control:
        # Pimcore admin ACl  // DO NOT CHANGE!
        - { path: ^/admin/settings/display-custom-logo, roles: PUBLIC_ACCESS }
        - { path: ^/admin/login/2fa-verify, roles: IS_AUTHENTICATED_2FA_IN_PROGRESS }
        - { path: ^/admin/login/2fa-setup, roles: ROLE_PIMCORE_USER }
        - { path: ^/admin/login/2fa, roles: IS_AUTHENTICATED_2FA_IN_PROGRESS }
        - { path: ^/admin/login$, roles: PUBLIC_ACCESS }
        - { path: ^/admin/login/(login|lostpassword|deeplink|csrf-token)$, roles: PUBLIC_ACCESS }
        - { path: ^/admin/login/2fa, roles: IS_AUTHENTICATED_2FA_IN_PROGRESS }

        # Маршруты Keycloak
        - { path: ^/admin/keycloak, roles: PUBLIC_ACCESS }

        # Защищенный административный интерфейс
        - { path: ^/admin, roles: ROLE_PIMCORE_USER }
        - { path: ^/asset/webdav, roles: ROLE_PIMCORE_USER }

    role_hierarchy:
        # Pimcore admin  // DO NOT CHANGE!
        ROLE_PIMCORE_ADMIN: [ROLE_PIMCORE_USER]

```

6. **Добавьте маршруты в конфигурацию**

```yaml
# config/routes.yaml
iperson1337_pimcore_keycloak_auth_connect:
    path: /auth/keycloak/connect
    controller: Iperson1337\PimcoreKeycloakBundle\Controller\KeycloakController::connectAction

iperson1337_pimcore_keycloak_auth_check:
    path: /auth/keycloak/check
    controller: Iperson1337\PimcoreKeycloakBundle\Controller\KeycloakController::checkAction

iperson1337_pimcore_keycloak_auth_logout:
    path: /auth/keycloak/logout
    controller: Iperson1337\PimcoreKeycloakBundle\Controller\KeycloakController::logoutAction
```

7. **Обновите cookie_samesite для поддержки OAuth2**

```yaml
# config/packages/framework.yaml
framework:
    session:
        cookie_samesite: 'lax'  # Требуется для работы OAuth2 редиректов
```

8. **Очистите кэш**

```bash
bin/console cache:clear
```

## Настройка Keycloak

1. Создайте новый клиент в Keycloak
2. Установите Client ID как `pimcore-admin` (или то, что указано в конфигурации)
3. Установите Access Type как `confidential`
4. Включите "Standard Flow" и "Direct Access Grants"
5. Установите Valid Redirect URIs как `https://your-pimcore-domain.com/auth/keycloak/check`
6. После сохранения перейдите на вкладку Credentials для получения Client Secret

## Маппинг пользователей

Когда пользователь впервые входит через Keycloak, соответствующий пользователь Pimcore создается автоматически (если включена опция `auto_create_users`) со следующим маппингом:

- Keycloak preferred_username → Pimcore username
- Keycloak email → Pimcore email
- Keycloak given_name → Pimcore firstname
- Keycloak family_name → Pimcore lastname

## Маппинг ролей

Бандл автоматически преобразует роли Keycloak в роли Symfony Security. Например:

- Роль `admin` в Keycloak преобразуется в `ROLE_ADMIN` и `ROLE_PIMCORE_ADMIN` в Symfony и устанавливает флаг admin для пользователя Pimcore
- Другие роли Keycloak преобразуются с префиксом `ROLE_`

## Расширение функциональности

Для настройки более сложной логики маппинга ролей вы можете расширить сервис `UserMapperService`:

```php
// src/Service/CustomUserMapperService.php
namespace App\Service;

use Pimcore\Model\User;
use Psr\Log\LoggerInterface;
use Iperson1337\PimcoreKeycloakBundle\Provider\KeycloakResourceOwner;
use Iperson1337\PimcoreKeycloakBundle\Service\UserMapperService;

class CustomUserMapperService extends UserMapperService
{
    public function __construct(LoggerInterface $logger)
    {
        parent::__construct($logger);
    }

    protected function syncUserRoles(User $user, array $keycloakRoles): void
    {
        parent::syncUserRoles($user, $keycloakRoles);

        // Ваша собственная логика маппинга ролей
        if (in_array('content-editor', $keycloakRoles, true)) {
            // Назначаем пользователю соответствующие роли Pimcore
            $user->setRoles(['contentEditor', 'reviewer']);
        }
    }
}
```

Затем зарегистрируйте ваш сервис в `services.yaml`:

```yaml
services:
    Iperson1337\PimcoreKeycloakBundle\Service\UserMapperService:
        class: App\Service\CustomUserMapperService
        arguments:
            $logger: '@monolog.logger.keycloak'
```

## Поддержка Single Logout

Бандл поддерживает Single Logout - когда пользователь выходит из Pimcore, он также выходит из Keycloak. Для этого:

1. Убедитесь, что ваш logout route использует контроллер `iperson1337_pimcore_keycloak_auth_logout`
2. Или настройте ваш собственный logout handler, который будет включать вызов Keycloak endpoints

## Логирование

Бандл использует отдельный канал логирования `keycloak`. Вы можете настроить его в `monolog.yaml`:

```yaml
monolog:
    handlers:
        keycloak:
            type: rotating_file
            path: "%kernel.logs_dir%/keycloak.log"
            level: debug
            channels: [keycloak]
            max_files: 10
```

## Безопасность и рекомендации

1. Всегда включайте SSL-верификацию в продакшн-окружении (`ssl_verification: true`)
2. Регулярно проверяйте и обновляйте клиентские секреты Keycloak
3. Используйте HTTPS для всех взаимодействий между Pimcore и Keycloak
4. Ограничьте список разрешенных редиректов в настройках клиента Keycloak

## Устранение неполадок

При возникновении проблем проверьте:

1. Правильность настроек клиента в Keycloak
2. Корректность URL-адресов и разрешенных редиректов
3. Настройки scope и mappers в Keycloak
4. Логи в файле keycloak.log

Дополнительные руководства по устранению неполадок доступны в документации в папке `docs/`.
