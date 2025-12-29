<?php

namespace Kode\Jwt\Contract;

interface Arrayable
{
    /**
     * 将对象转换为数组
     *
     * @return array<string, mixed>
     */
    public function toArray(): array;

    /**
     * 从数组创建对象实例
     *
     * @param array<string, mixed> $data 数据数组
     * @return static
     */
    public static function fromArray(array $data): static;
}
