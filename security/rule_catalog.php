<?php
/** Versioned, local catalogue shared by the event journal and the operator console. */
final class CyberShieldRuleCatalog
{
    private static $catalog = null;

    public static function rules(): array
    {
        if (self::$catalog !== null) { return self::$catalog; }
        $path = __DIR__ . '/../config/security-rules.json';
        $contents = @file_get_contents($path);
        $decoded = is_string($contents) ? json_decode($contents, true) : null;
        if (!is_array($decoded) || (int) ($decoded['version'] ?? 0) !== 1 || !is_array($decoded['rules'] ?? null)) {
            throw new RuntimeException('Le catalogue local des règles est invalide.');
        }
        $rules = [];
        foreach ($decoded['rules'] as $rule) {
            if (!is_array($rule) || !preg_match('/^CS-[A-Z0-9-]{3,24}$/D', (string) ($rule['id'] ?? '')) || isset($rules[$rule['id']])) {
                throw new RuntimeException('Le catalogue contient une règle invalide ou dupliquée.');
            }
            foreach (['name', 'severity', 'category', 'description', 'remediation'] as $field) {
                if (!is_string($rule[$field] ?? null) || trim($rule[$field]) === '') {
                    throw new RuntimeException('Le catalogue contient une définition de règle incomplète.');
                }
            }
            $rules[$rule['id']] = $rule;
        }
        return self::$catalog = $rules;
    }

    public static function forEvent(array $event): array
    {
        $attackType = strtoupper((string) ($event['attack_type'] ?? $event['type'] ?? 'NONE'));
        $patterns = is_array($event['patterns'] ?? null) ? $event['patterns'] : [];
        $patterns = array_map(static fn($value): string => strtoupper(is_scalar($value) ? (string) $value : ''), $patterns);
        $matches = [];
        foreach (self::rules() as $id => $rule) {
            if (in_array($attackType, $rule['attack_types'] ?? [], true) || array_intersect($patterns, $rule['patterns'] ?? [])) {
                $matches[$id] = $rule;
            }
        }
        $action = strtoupper((string) ($event['action'] ?? ''));
        $source = strtolower((string) ($event['source'] ?? ''));
        $modelBlocked = $action === 'BLOCKED_BY_AI' || ($action === 'MONITORED' && !empty($event['would_block']));
        if (!$matches && $modelBlocked && in_array($source, ['ai', 'mlp'], true)) {
            $matches['CS-MLP-001'] = self::rules()['CS-MLP-001'];
        }
        if (!$matches && $source === 'fail_safe' && in_array($action, ['BLOCKED', 'MONITORED'], true) && !empty($event['would_block'])) {
            $matches['CS-OPS-005'] = self::rules()['CS-OPS-005'];
        }
        return array_values($matches);
    }

    public static function enrich(array $event): array
    {
        $rules = self::forEvent($event);
        if (!$rules) {
            return array_merge($event, ['rule_ids' => [], 'rule_id' => null, 'rule_name' => null, 'severity' => null,
                'category' => null, 'cwe' => null, 'owasp' => null, 'rule_description' => null,
                'rule_remediation' => null, 'reviewable' => false, 'finding_fingerprint' => null]);
        }
        $ids = array_column($rules, 'id');
        sort($ids, SORT_STRING);
        $primary = $rules[0];
        $route = preg_split('/[?#]/', (string) ($event['path'] ?? '/'), 2)[0];
        $route = preg_replace('~/[0-9]+(?=/|$)~', '/{id}', $route);
        $route = preg_replace('~/[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)~i', '/{uuid}', $route);
        $method = strtoupper((string) ($event['method'] ?? 'OTHER'));
        if (!preg_match('/^[A-Z]{1,12}$/D', $method)) { $method = 'OTHER'; }
        $source = strtolower((string) ($event['source'] ?? 'other'));
        if (!in_array($source, ['heuristic', 'ai', 'mlp', 'ip_policy', 'fail_safe'], true)) { $source = 'other'; }
        $fingerprintData = "v1\n" . implode(',', $ids) . "\n" . $method . "\n" . substr($route, 0, 300) . "\n" . $source;
        return array_merge($event, [
            'rule_ids' => $ids, 'rule_id' => $primary['id'], 'rule_name' => $primary['name'],
            'severity' => $primary['severity'], 'category' => $primary['category'],
            'cwe' => $primary['cwe'] ?? null, 'owasp' => $primary['owasp'] ?? null,
            'rule_description' => $primary['description'], 'rule_remediation' => $primary['remediation'],
            'reviewable' => (bool) ($primary['reviewable'] ?? false),
            'finding_fingerprint' => hash('sha256', $fingerprintData),
        ]);
    }
}
