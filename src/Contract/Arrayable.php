<?php

namespace Kode\Jwt\Contract;

interface Arrayable
{
    /**
     * 将对象转换为数组
     */
    public function toArray(): array;
    
    /**
     * 从数组创建对象实例
     */
    public static function fromArray(array $data): static;
}