<?php
declare(strict_types=1);

/** Frontière SQL : chaque opération applicative passe par une requête préparée. */
final class SecureDataGateway {
    private mysqli $connection;

    public function __construct(mysqli $connection) { $this->connection = $connection; }

    public function execute(string $sql, array $params = []) {
        $stmt = $this->connection->prepare($sql);
        try {
            if ($params) {
                $types = '';
                foreach ($params as $param) {
                    $types .= is_int($param) ? 'i' : (is_float($param) ? 'd' : 's');
                }
                $stmt->bind_param($types, ...$params);
            }
            $stmt->execute();
            return $stmt->field_count > 0 ? $stmt->get_result() : true;
        } finally {
            $stmt->close();
        }
    }
}
