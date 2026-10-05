<?php

declare(strict_types=1);

namespace App\Infrastructure\Database;

use PDO;

/**
 * Factory pour la création de services de base de données
 * Pattern Factory + Singleton pour une gestion centralisée
 */
final class DatabaseFactory
{
    private static ?ConnectionPool $connectionPool = null;
    private static ?QueryBuilder $queryBuilder = null;
    private static ?TransactionManager $transactionManager = null;
    private static ?PerformanceMonitor $performanceMonitor = null;
    private static ?SchemaManager $schemaManager = null;
    
    /**
     * Obtient le pool de connexions (Singleton)
     */
    public static function getConnectionPool(): ConnectionPool
    {
        if (self::$connectionPool === null) {
            self::$connectionPool = new ConnectionPool();
        }
        
        return self::$connectionPool;
    }
    
    /**
     * Obtient une connexion pour les opérations d'écriture
     */
    public static function getWriteConnection(): PDO
    {
        return self::getConnectionPool()->getMaster();
    }
    
    /**
     * Obtient une connexion pour les opérations de lecture
     */
    public static function getReadConnection(): PDO
    {
        return self::getConnectionPool()->getReplica();
    }
    
    /**
     * Builder de requêtes SQL sécurisé
     */
    public static function getQueryBuilder(): QueryBuilder
    {
        if (self::$queryBuilder === null) {
            self::$queryBuilder = new QueryBuilder(self::getReadConnection());
        }
        
        return self::$queryBuilder;
    }
    
    /**
     * Gestionnaire de transactions distribué
     */
    public static function getTransactionManager(): TransactionManager
    {
        if (self::$transactionManager === null) {
            self::$transactionManager = new TransactionManager(self::getWriteConnection());
        }
        
        return self::$transactionManager;
    }
    
    /**
     * Service de monitoring des performances
     */
    public static function getPerformanceMonitor(): PerformanceMonitor
    {
        if (self::$performanceMonitor === null) {
            self::$performanceMonitor = new PerformanceMonitor(self::getConnectionPool());
        }
        
        return self::$performanceMonitor;
    }
    
    /**
     * Migrations et schémas
     */
    public static function getSchemaManager(): SchemaManager
    {
        if (self::$schemaManager === null) {
            self::$schemaManager = new SchemaManager(self::getWriteConnection());
        }
        
        return self::$schemaManager;
    }
    
    /**
     * Réinitialise toutes les instances (pour les tests)
     */
    public static function reset(): void
    {
        self::$connectionPool = null;
        self::$queryBuilder = null;
        self::$transactionManager = null;
        self::$performanceMonitor = null;
        self::$schemaManager = null;
    }
}

// ==================== CLASSES DE SUPPORT ====================

/**
 * Builder de requêtes SQL avec protection contre les injections
 */
class QueryBuilder
{
    private PDO $connection;
    private array $queryLog = [];
    private array $currentQuery = [
        'select' => [],
        'from' => '',
        'where' => [],
        'orderBy' => [],
        'limit' => null,
        'offset' => null,
    ];
    
    public function __construct(PDO $connection)
    {
        $this->connection = $connection;
    }
    
    public function select(string $table, array $columns = ['*']): self
    {
        $this->currentQuery['select'] = $columns;
        $this->currentQuery['from'] = $table;
        return $this;
    }
    
    public function where(string $column, string $operator, $value): self
    {
        $this->currentQuery['where'][] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value
        ];
        return $this;
    }
    
    public function orderBy(string $column, string $direction = 'ASC'): self
    {
        $this->currentQuery['orderBy'][] = [
            'column' => $column,
            'direction' => $direction
        ];
        return $this;
    }
    
    public function limit(int $limit): self
    {
        $this->currentQuery['limit'] = $limit;
        return $this;
    }
    
    public function offset(int $offset): self
    {
        $this->currentQuery['offset'] = $offset;
        return $this;
    }
    
    public function execute(): array
    {
        $sql = $this->buildQuery();
        $params = $this->extractParams();
        
        $stmt = $this->connection->prepare($sql);
        $stmt->execute($params);
        
        $this->logQuery($sql, $params);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    private function buildQuery(): string
    {
        $sql = "SELECT " . implode(', ', $this->currentQuery['select']) . 
               " FROM " . $this->currentQuery['from'];
        
        if (!empty($this->currentQuery['where'])) {
            $conditions = [];
            foreach ($this->currentQuery['where'] as $index => $where) {
                $conditions[] = $where['column'] . ' ' . $where['operator'] . ' ?';
            }
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }
        
        if (!empty($this->currentQuery['orderBy'])) {
            $orders = [];
            foreach ($this->currentQuery['orderBy'] as $order) {
                $orders[] = $order['column'] . ' ' . $order['direction'];
            }
            $sql .= " ORDER BY " . implode(', ', $orders);
        }
        
        if ($this->currentQuery['limit'] !== null) {
            $sql .= " LIMIT " . $this->currentQuery['limit'];
        }
        
        if ($this->currentQuery['offset'] !== null) {
            $sql .= " OFFSET " . $this->currentQuery['offset'];
        }
        
        return $sql;
    }
    
    private function extractParams(): array
    {
        $params = [];
        foreach ($this->currentQuery['where'] as $where) {
            $params[] = $where['value'];
        }
        return $params;
    }
    
    private function logQuery(string $sql, array $params): void
    {
        $this->queryLog[] = [
            'sql' => $sql,
            'params' => $params,
            'timestamp' => microtime(true),
        ];
    }
    
    public function getQueryLog(): array
    {
        return $this->queryLog;
    }
    
    public function clearQueryLog(): void
    {
        $this->queryLog = [];
    }
}

/**
 * Gestionnaire de transactions avec support pour les transactions imbriquées
 */
class TransactionManager
{
    private PDO $connection;
    private int $transactionLevel = 0;
    private array $savepoints = [];
    
    public function __construct(PDO $connection)
    {
        $this->connection = $connection;
    }
    
    public function beginTransaction(): bool
    {
        if ($this->transactionLevel === 0) {
            $this->connection->beginTransaction();
        } else {
            $savepoint = 'SAVEPOINT_' . $this->transactionLevel;
            $this->connection->exec("SAVEPOINT $savepoint");
            $this->savepoints[] = $savepoint;
        }
        
        $this->transactionLevel++;
        return true;
    }
    
    public function commit(): bool
    {
        if ($this->transactionLevel === 1) {
            $result = $this->connection->commit();
        } else {
            $savepoint = array_pop($this->savepoints);
            $this->connection->exec("RELEASE SAVEPOINT $savepoint");
            $result = true;
        }
        
        $this->transactionLevel--;
        return $result;
    }
    
    public function rollback(): bool
    {
        if ($this->transactionLevel === 1) {
            $result = $this->connection->rollBack();
        } elseif ($this->transactionLevel > 1) {
            $savepoint = array_pop($this->savepoints);
            $this->connection->exec("ROLLBACK TO SAVEPOINT $savepoint");
            $result = true;
        } else {
            $result = false;
        }
        
        $this->transactionLevel = max(0, $this->transactionLevel - 1);
        return $result;
    }
    
    public function inTransaction(): bool
    {
        return $this->transactionLevel > 0;
    }
    
    public function getTransactionLevel(): int
    {
        return $this->transactionLevel;
    }
}

/**
 * Moniteur de performances de la base de données
 */
class PerformanceMonitor
{
    private ConnectionPool $pool;
    private array $metrics = [];
    private float $startTime;
    
    public function __construct(ConnectionPool $pool)
    {
        $this->pool = $pool;
        $this->startTime = microtime(true);
        $this->initializeMetrics();
    }
    
    private function initializeMetrics(): void
    {
        $this->metrics = [
            'start_time' => $this->startTime,
            'queries_executed' => 0,
            'slow_queries' => [],
            'connection_stats' => [],
        ];
    }
    
    public function calculateQPS(): float
    {
        $elapsed = microtime(true) - $this->metrics['start_time'];
        return $elapsed > 0 ? $this->metrics['queries_executed'] / $elapsed : 0;
    }
    
    public function getSlowQueries(float $threshold = 1.0): array
    {
        return array_filter($this->metrics['slow_queries'], 
            fn($query) => $query['execution_time'] > $threshold);
    }
    
    public function recordQuery(string $sql, float $executionTime): void
    {
        $this->metrics['queries_executed']++;
        
        if ($executionTime > 1.0) { // Seuil de 1 seconde
            $this->metrics['slow_queries'][] = [
                'sql' => $sql,
                'execution_time' => $executionTime,
                'timestamp' => microtime(true),
            ];
        }
    }
    
    public function updateConnectionStats(): void
    {
        $this->metrics['connection_stats'] = $this->pool->healthCheck();
    }
    
    public function collectMetrics(): array
    {
        $this->updateConnectionStats();
        
        return [
            'connections' => $this->metrics['connection_stats'],
            'queries_per_second' => $this->calculateQPS(),
            'slow_queries' => $this->getSlowQueries(),
            'total_queries' => $this->metrics['queries_executed'],
            'uptime_seconds' => microtime(true) - $this->metrics['start_time'],
            'timestamp' => date('c'),
        ];
    }
    
    public function reset(): void
    {
        $this->initializeMetrics();
    }
}

/**
 * Gestionnaire de schémas de base de données
 */
class SchemaManager
{
    private PDO $connection;
    
    public function __construct(PDO $connection)
    {
        $this->connection = $connection;
    }
    
    public function migrate(array $migrations): void
    {
        $this->connection->beginTransaction();
        
        try {
            foreach ($migrations as $name => $sql) {
                $this->connection->exec($sql);
                $this->logMigration($name);
            }
            
            $this->connection->commit();
        } catch (\PDOException $e) {
            $this->connection->rollBack();
            throw new \RuntimeException("Migration failed: " . $e->getMessage());
        }
    }
    
    private function logMigration(string $name): void
    {
        $stmt = $this->connection->prepare(
            "INSERT INTO schema_migrations (name, executed_at) VALUES (?, NOW())"
        );
        $stmt->execute([$name]);
    }
    
    public function createTable(string $tableName, array $columns): void
    {
        $columnDefs = [];
        foreach ($columns as $name => $definition) {
            $columnDefs[] = "$name $definition";
        }
        
        $sql = "CREATE TABLE IF NOT EXISTS $tableName (" . 
               implode(', ', $columnDefs) . ")";
        
        $this->connection->exec($sql);
    }
    
    public function dropTable(string $tableName): void
    {
        $sql = "DROP TABLE IF EXISTS $tableName";
        $this->connection->exec($sql);
    }
    
    public function addColumn(string $tableName, string $columnName, string $definition): void
    {
        $sql = "ALTER TABLE $tableName ADD COLUMN $columnName $definition";
        $this->connection->exec($sql);
    }
    
    public function getTableSchema(string $tableName): array
    {
        $stmt = $this->connection->prepare("DESCRIBE $tableName");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function tableExists(string $tableName): bool
    {
        try {
            $stmt = $this->connection->prepare("SELECT 1 FROM $tableName LIMIT 1");
            $stmt->execute();
            return true;
        } catch (\PDOException) {
            return false;
        }
    }
}