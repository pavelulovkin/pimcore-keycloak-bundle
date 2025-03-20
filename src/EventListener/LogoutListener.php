<?php

namespace Iperson1337\PimcoreKeycloakBundle\EventListener;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Iperson1337\PimcoreKeycloakBundle\Security\User\KeycloakUser;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

readonly class LogoutListener
{
    public function __construct(
        private ClientRegistry        $clientRegistry,
        private UrlGeneratorInterface $urlGenerator,
        private TokenStorageInterface $tokenStorage,
        private string                $defaultTargetRouteName
    ) {
    }

    public function onSymfonyComponentSecurityHttpEventLogoutEvent(LogoutEvent $event): void
    {
        if (null === $event->getToken() || null === $event->getToken()->getUser()) {
            return;
        }

        $user = $event->getToken()->getUser();
        if (!$user instanceof KeycloakUser) {
            return;
        }

        $oAuth2Provider = $this->clientRegistry->getClient('keycloak')->getOAuth2Provider();
        $logoutUrl = $oAuth2Provider->getLogoutUrl([
            'state' => $user->getAccessToken()->getValues()['session_state'],
            'access_token' => $user->getAccessToken(),
            'redirect_uri' => str_replace('http://', 'https://', $this->urlGenerator->generate($this->defaultTargetRouteName, [], UrlGeneratorInterface::ABSOLUTE_URL))
        ]);

        $this->tokenStorage->setToken(null);
        $event->getRequest()->getSession()->invalidate();

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
