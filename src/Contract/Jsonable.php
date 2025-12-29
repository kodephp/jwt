<?php

namespace Kode\Jwt\Contract;

interface Jsonable
{
    /**
     * 将对象转换为JSON字符串
     */
    public function toJson(int $options = 0): string;

    /**
     * 从JSON字符串创建对象实例
     */
    public static function fromJson(string $json): static;
}
