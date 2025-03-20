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
}
