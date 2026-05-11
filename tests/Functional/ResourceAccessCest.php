<?php

declare(strict_types=1);

namespace Blackcube\Oauth2\Tests\Functional;

use Blackcube\Oauth2\Jwt\JwtService;
use Blackcube\Oauth2\Middlewares\JwtValidatorMiddleware;
use Blackcube\Oauth2\Tests\Support\DatabaseCestTrait;
use Blackcube\Oauth2\Tests\Support\FunctionalTester;
use Blackcube\Oauth2\Tests\Support\TestCypherKey;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use HttpSoft\Message\ServerRequestFactory;
use HttpSoft\Message\ResponseFactory;
use HttpSoft\Message\StreamFactory;

final class ResourceAccessCest
{
    use DatabaseCestTrait;

    private ?JwtService $jwtService = null;

    private static bool $dataSeeded = false;

    private function ensureJwtService(): JwtService
    {
        return $this->jwtService ??= new JwtService();
    }

    private function ensureTestData(): void
    {
        if (self::$dataSeeded) {
            return;
        }

        $cypherKey = new TestCypherKey();
        $cypherKey->setId('test-issuer');
        $cypherKey->setPublicKey(file_get_contents(__DIR__ . '/../keys/public.pem'));
        $cypherKey->setPrivateKey(file_get_contents(__DIR__ . '/../keys/private.pem'));
        $cypherKey->setAlgorithm('RS256');
        $cypherKey->setIsDefault(true);
        $cypherKey->setDateCreate(date('Y-m-d H:i:s'));
        $cypherKey->save();

        self::$dataSeeded = true;
    }

    public function testValidTokenAllowsAccess(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $cypherKey = TestCypherKey::queryById('test-issuer');

        $token = $this->ensureJwtService()->encode(
            cypherKey: $cypherKey,
            subject: '1',
            issuer: 'test-issuer',
            audience: 'test-audience',
            scopes: ['read'],
            ttl: 3600
        );

        $requestFactory = new ServerRequestFactory();
        $request = $requestFactory->createServerRequest('GET', '/api/resource');
        $request = $request->withHeader('Authorization', 'Bearer ' . $token);

        $capturedRequest = null;
        $handler = new class ($capturedRequest) implements RequestHandlerInterface {
            public function __construct(private ?ServerRequestInterface &$captured)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->captured = $request;
                return (new ResponseFactory())->createResponse(200);
            }
        };

        $middleware = new JwtValidatorMiddleware(
            cypherKeyClass: TestCypherKey::class,
            clock: new class implements ClockInterface {
                public function now(): DateTimeImmutable
                {
                    return new DateTimeImmutable();
                }
            },
            responseFactory: new ResponseFactory(),
            streamFactory: new StreamFactory()
        );

        $response = $middleware->process($request, $handler);

        $I->assertEquals(200, $response->getStatusCode());
        $I->assertNotNull($capturedRequest);
        $I->assertEquals('1', $capturedRequest->getAttribute('userId'));
        $I->assertEquals('test-issuer', $capturedRequest->getAttribute('population'));
    }

    public function testMissingTokenReturns401(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $requestFactory = new ServerRequestFactory();
        $request = $requestFactory->createServerRequest('GET', '/api/resource');

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse(200);
            }
        };

        $middleware = new JwtValidatorMiddleware(
            cypherKeyClass: TestCypherKey::class,
            clock: new class implements ClockInterface {
                public function now(): DateTimeImmutable
                {
                    return new DateTimeImmutable();
                }
            },
            responseFactory: new ResponseFactory(),
            streamFactory: new StreamFactory()
        );

        $response = $middleware->process($request, $handler);

        $I->assertEquals(401, $response->getStatusCode());
    }

    public function testInvalidTokenReturns401(FunctionalTester $I): void
    {
        $this->ensureTestData();
        $requestFactory = new ServerRequestFactory();
        $request = $requestFactory->createServerRequest('GET', '/api/resource');
        $request = $request->withHeader('Authorization', 'Bearer invalid.token.here');

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse(200);
            }
        };

        $middleware = new JwtValidatorMiddleware(
            cypherKeyClass: TestCypherKey::class,
            clock: new class implements ClockInterface {
                public function now(): DateTimeImmutable
                {
                    return new DateTimeImmutable();
                }
            },
            responseFactory: new ResponseFactory(),
            streamFactory: new StreamFactory()
        );

        $response = $middleware->process($request, $handler);

        $I->assertEquals(401, $response->getStatusCode());
    }
}
