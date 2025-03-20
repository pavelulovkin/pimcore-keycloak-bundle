<?php

namespace Iperson1337\PimcoreKeycloakBundle\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\RouterInterface;

class KeycloakController extends AbstractController
{
    public function __construct(
        private readonly ClientRegistry $clientRegistry,
        private readonly RouterInterface $router,
        private readonly LoggerInterface $logger
    ) {
    }

    public function connectAction(Request $request, ClientRegistry $clientRegistry): RedirectResponse
    {
        try {
            return $clientRegistry->getClient('keycloak')->redirect();
        } catch (\Exception $e) {
            $this->logger->error('Error initiating Keycloak authentication: ' . $e->getMessage());
            return $this->redirectToRoute('pimcore_admin_login', [
                'login_error' => 'Ошибка подключения к Keycloak. Пожалуйста, попробуйте позже.'
            ]);
        }
    }

    public function checkAction(Request $request): Response
    {
        $loginReferrer = null;
        if ($request->hasSession()) {
            $loginReferrer = $request->getSession()->remove('loginReferrer');
        }

        return $loginReferrer ? $this->redirect($loginReferrer) : $this->redirectToRoute('pimcore_admin_index');
    }

    /**
     * Обрабатывает выход из системы, включая выход из Keycloak
     *
     * Если включен Single Logout, перенаправляет пользователя
     * на endpoint выхода из Keycloak
     */
    public function logoutAction(Request $request): Response
    {
        try {
            // Проверяем, есть ли ID токен в сессии
            $idToken = $this->getSession()->get('keycloak_id_token');

            // Если у нас нет ID токена, просто выполняем стандартный logout
            if (!$idToken) {
                $this->logger->debug('No ID token found, performing standard logout');
                return $this->redirectToRoute('pimcore_admin_logout');
            }

            // Получаем клиент OAuth и провайдер
            $client = $this->clientRegistry->getClient('keycloak');
            $provider = $client->getOAuth2Provider();

            // Создаем URL для выхода из Keycloak
            $logoutUrl = $provider->getLogoutUrl([
                'id_token_hint' => $idToken,
                'post_logout_redirect_uri' => $this->generateUrl(
                    'pimcore_admin_login',
                    [],
                    RouterInterface::ABSOLUTE_URL
                )
            ]);

            // Удаляем токен из сессии
            $this->getSession()->remove('keycloak_id_token');

            // Перенаправляем на URL выхода из Keycloak
            return new RedirectResponse($logoutUrl);

        } catch (\Exception $e) {
            $this->logger->error('Error during Keycloak logout', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            // В случае ошибки выполняем стандартный выход
            return $this->redirectToRoute('pimcore_admin_logout');
        }
    }

    /**
     * Получает сессию
     */
    private function getSession()
    {
        $request = $this->container->get('request_stack')->getCurrentRequest();
        return $request->getSession();
    }

    #[Route('/auth/keycloak/diagnostic', name: 'iperson1337_pimcore_keycloak_diagnostic')]
    public function diagnosticAction(Request $request): JsonResponse
    {
        $diagnosticInfo = [
            'environment' => [
                'php_version' => PHP_VERSION,
                'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'host' => $request->getHost(),
                'base_url' => $request->getSchemeAndHttpHost(),
            ],
            'oauth_client' => [
                'client_exists' => $this->clientRegistry->getClient('keycloak'),
            ],
            'keycloak_provider' => [],
            'routes' => [
                'connect_route' => 'iperson1337_pimcore_keycloak_auth_connect',
                'check_route' => 'iperson1337_pimcore_keycloak_auth_check',
                'logout_route' => 'iperson1337_pimcore_keycloak_auth_logout',
            ],
            'session' => [
                'has_session' => $request->hasSession(),
                'session_id' => $request->hasSession() ? $request->getSession()->getId() : null,
                'session_active' => $request->hasSession() && $request->getSession()->isStarted(),
            ],
        ];

        // Проверяем клиент OAuth2
        if ($diagnosticInfo['oauth_client']['client_exists']) {
            try {
                $client = $this->clientRegistry->getClient('keycloak');
                $diagnosticInfo['oauth_client']['client_class'] = get_class($client);

                $provider = $client->getOAuth2Provider();
                $diagnosticInfo['oauth_client']['provider_class'] = get_class($provider);

                // Тестируем создание URL авторизации
                $authUrl = $provider->getAuthorizationUrl(['scope' => ['openid', 'profile', 'email']]);
                $diagnosticInfo['oauth_client']['auth_url_works'] = !empty($authUrl);
                $diagnosticInfo['oauth_client']['auth_url_sample'] = $authUrl;

                // Проверяем keycloak-специфичные методы
                if (method_exists($provider, 'getLogoutUrl')) {
                    $logoutUrl = $provider->getLogoutUrl();
                    $diagnosticInfo['oauth_client']['logout_url_works'] = !empty($logoutUrl);
                    $diagnosticInfo['oauth_client']['logout_url_sample'] = $logoutUrl;
                }

                // Проверяем параметры провайдера
                foreach (['auth_server_url', 'realm', 'auth_server_public_url', 'auth_server_private_url'] as $key) {
                    if (property_exists($provider, $key) || method_exists($provider, 'get' . ucfirst($key))) {
                        $method = 'get' . ucfirst($key);
                        $diagnosticInfo['keycloak_provider'][$key] = method_exists($provider, $method) ?
                            $provider->$method() :
                            $provider->$key ?? 'Undefined';
                    }
                }
            } catch (\Exception $e) {
                $diagnosticInfo['oauth_client']['error'] = $e->getMessage();
                $diagnosticInfo['oauth_client']['trace'] = $e->getTraceAsString();
            }
        }

        // Проверяем переменные окружения (скрываем секретные значения)
        $envVars = [
            'KEYCLOAK_CLIENT_ID',
            'KEYCLOAK_SERVER_BASE_URL',
            'KEYCLOAK_SERVER_PUBLIC_BASE_URL',
            'KEYCLOAK_SERVER_PRIVATE_BASE_URL',
            'KEYCLOAK_REALM',
        ];

        foreach ($envVars as $var) {
            $diagnosticInfo['environment']['env_' . strtolower($var)] = !empty($_ENV[$var]) ? 'Set' : 'Not set';
        }

        return new JsonResponse($diagnosticInfo);
    }
}
