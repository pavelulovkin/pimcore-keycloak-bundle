<?php

namespace Iperson1337\PimcoreKeycloakBundle\EventListener;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

readonly class ExceptionListener
{
    public function __construct(
        private UrlGeneratorInterface $urlGenerator,
        private LoggerInterface       $logger
    ) {
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();

        if ($exception instanceof IdentityProviderException) {
            $this->logger->error('Ошибка OAuth провайдера: ' . $exception->getMessage());

            $event->setResponse(new RedirectResponse(
                $this->urlGenerator->generate('iperson1337_pimcore_keycloak_auth_connect')
            ));
        } elseif ($exception instanceof AuthenticationException) {
            $this->logger->error('Ошибка аутентификации: ' . $exception->getMessage());

            $event->setResponse(new RedirectResponse(
                $this->urlGenerator->generate('iperson1337_pimcore_keycloak_auth_connect')
            ));
        }
    }
}
