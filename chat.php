<?php

use Firebase\JWT\JWT;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/vendor/autoload.php';

// Slim Setup
$app = AppFactory::create();

// Routes
$app->post('/login', 'login');
$app->get('/messages/{user_id}', 'getMessages');
$app->post('/messages/{user_id}', 'sendMessage');

$app->run();

// Initialize SQLite DB
$db = new SQLite3('chat.db');

// Function Starts Here
function login(Request $request, Response $response, $args)
{
    $data = $request->getParsedBody();
    $username = $data['username'];
    $password = $data['password'];

    // Check if the user exists in the database
    $stmt = $db->prepare('SELECT id FROM users WHERE username=:username AND password=:password');
    $stmt->bindValue(':username', $username);
    $stmt->bindValue(':password', $password);
    $result = $stmt->execute()->fetchArray();

    if (!$result) {
        return $response->withStatus(401)->withJson(['error' => 'Invalid username or password']);
    }

    // Generate a JWT token for the user
    $token = JWT::encode(['user_id' => $result['id']], 'secret');

    return $response->withJson(['token' => $token]);
}

function getMessages(Request $request, Response $response, $args)
{
    $user_id = $args['user_id'];

    // Verify the JWT token to ensure the user is authorized
    $token = $request->getHeaderLine('Authorization');
    try {
        $decoded = JWT::decode($token, 'secret', ['HS256']);
    } catch (Exception $e) {
        return $response->withStatus(401)->withJson(['error' => 'Unauthorized']);
    }

    // Get all messages sent to the user
    $stmt = $db->prepare('SELECT messages.message, users.username FROM messages INNER JOIN users ON messages.sender_id=users.id WHERE messages.receiver_id=:receiver_id');
    $stmt->bindValue(':receiver_id', $user_id);
    $result = $stmt->execute();

    $messages = [];
    while ($row = $result->fetchArray()) {
        $messages[] = ['message' => $row['message'], 'author' => $row['username']];
    }

    return $response->withJson($messages);
}

function sendMessage(Request $request, Response $response, $args)
{
    $user_id = $args['user_id'];
    $data = $request->getParsedBody();
    $message = $data['message'];

    // Verify the JWT token to ensure the user is authorized
    $token = $request->getHeaderLine('Authorization');
    try {
        $decoded = JWT::decode($token, 'secret', ['HS256']);
    } catch (Exception $e) {
        return $response->withStatus(401)->withJson(['error' => 'Unauthorized']);
    }

    // Insert the message into the database
    $stmt = $db->prepare('INSERT INTO messages (sender_id, receiver_id, message) VALUES (:sender_id, :receiver_id, :message)');
    $stmt->bindValue(':sender_id', $decoded->user_id);
}
