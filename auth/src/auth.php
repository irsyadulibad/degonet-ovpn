<?php

use DegonetOvpn\Auth\Services\AuthService;
use DegonetOvpn\Auth\Services\CCDService;
use DegonetOvpn\Auth\Utils\DatabaseUtil;
use Dotenv\Dotenv;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Style\SymfonyStyle;

require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv::createMutable(__DIR__ . '/../');
$dotenv->load();

DatabaseUtil::initConnection();

$auth = new AuthService;

if (!isset($_SERVER['username']) && PHP_SAPI === 'cli' && (($argv[1] ?? null) === 'add')) {
    $io = new SymfonyStyle(new ArgvInput, new ConsoleOutput);

    $newUsername = $argv[2] ?? null;
    $newIp = $argv[3] ?? null;
    $newPassword = $argv[4] ?? null;
    $defaultNetmask = $_ENV['DEFAULT_NETMASK'] ?? '255.255.255.0';
    $newNetmask = $argv[5] ?? $defaultNetmask;

    if (!$newUsername || !$newIp) {
        $io->title('Add OpenVPN User');
        $io->error('Usage: ./auth add <username> <ip> [password] [netmask]');
        $io->writeln('Contoh: ./auth add budi 10.8.0.10 rahasia 255.255.255.0');
        exit(1);
    }

    if (!filter_var($newIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $io->error('IP tidak valid. Gunakan format IPv4, contoh: 10.8.0.10');
        exit(1);
    }

    if (!filter_var($newNetmask, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $io->error('Netmask tidak valid. Gunakan format IPv4, contoh: 255.255.255.0');
        exit(1);
    }

    if (!$newPassword) {
        $newPassword = $newUsername;
    }

    $user = $auth->addUser($newUsername, $newPassword, $newIp, $newNetmask);

    if (!$user) {
        $io->error("User '{$newUsername}' sudah ada.");
        exit(1);
    }

    $createdCcd = CCDService::create($user);

    $io->title('User berhasil ditambahkan');
    $io->success("Username: {$user->username}");
    $io->listing([
        "IP: {$user->ip}",
        "Netmask: {$user->netmask}",
        'Password: menggunakan argumen ke-4 atau default sama dengan username',
    ]);

    if (!$createdCcd) {
        $io->warning('User DB berhasil ditambah, tapi file CCD sudah ada sehingga tidak dibuat ulang.');
    }

    exit(0);
}

$username = $_SERVER['username'] ?? 'testing';
$password = $_SERVER['password'] ?? 'testing123';

if ($user = $auth->login($username, $password)) {
    CCDService::create($user);

    echo 'Login successful' . PHP_EOL;
    exit(0);
} else {
    echo 'Login failed' . PHP_EOL;
    exit(1);
}
