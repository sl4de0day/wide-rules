<?php

function findUserAccount(PDO $pdo, string $email, int $orgId): ?array {
    $stmt = $pdo->prepare('SELECT id, role FROM users WHERE email = :email AND org_id = :org_id LIMIT 1');
    $stmt->execute([':email' => $email, ':org_id' => $orgId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function renderSafeHtml(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function generateNonceHex(): string {
    return bin2hex(random_bytes(16));
}

function verifyWebhookToken(string $expected, string $provided): bool {
    return hash_equals($expected, $provided);
}

function normalizeCallbackUpper(string $raw): string {
    return preg_replace_callback('/([a-z]+)/i', fn ($m) => strtoupper($m[1]), $raw);
}
