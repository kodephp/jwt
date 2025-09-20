<?php

namespace Kode\Jwt\Event;

abstract class BaseEvent
{
    public function __construct(
        public readonly string $name,
        public readonly array $data = []
    ) {
    }
    
    /**
     * 获取事件名称
     */
    public function getName(): string
    {
        return $this->name;
    }
    
    /**
     * 获取事件数据
     */
    public function getData(): array
    {
        return $this->data;
    }
    
    /**
     * 获取事件数据中的指定键值
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }
    
    /**
     * 检查事件数据中是否存在指定键
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }
    
    /**
     * 将事件转换为数组
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'data' => $this->data,
            'timestamp' => microtime(true),
        ];
    }
}