<?php

declare(strict_types=1);

namespace Kode\Jwt\Support;

use Kode\Jwt\Contract\Arrayable;

/**
 * 不可变数据传输对象基类
 *
 * PHP 8.5+ 使用 clone with 语法实现高效不可变更新
 * PHP 8.1-8.4 使用传统 clone + 属性赋值方式
 */
abstract class ImmutableDto implements Arrayable
{
    /**
     * 创建带有修改属性的副本
     *
     * PHP 8.5+ 可使用: clone $this with { property: $value }
     * PHP 8.1-8.4 使用反射方式实现
     *
     * @param array<string, mixed> $changes 要修改的属性
     */
    public function with(array $changes): static
    {
        $reflection = new \ReflectionClass($this);
        $properties = $reflection->getProperties();

        $newProps = [];
        foreach ($properties as $property) {
            $name = $property->getName();
            $property->setAccessible(true);

            if (array_key_exists($name, $changes)) {
                $newProps[$name] = $changes[$name];
            } else {
                $newProps[$name] = $property->getValue($this);
            }
        }

        return new static(...$newProps);
    }

    /**
     * 创建带有单个属性修改的副本
     */
    public function withProperty(string $name, mixed $value): static
    {
        return $this->with([$name => $value]);
    }

    /**
     * 转换为数组
     */
    public function toArray(): array
    {
        $reflection = new \ReflectionClass($this);
        $properties = $reflection->getProperties();
        $result = [];

        foreach ($properties as $property) {
            $property->setAccessible(true);
            $result[$property->getName()] = $property->getValue($this);
        }

        return $result;
    }

    /**
     * 转换为 JSON
     */
    public function toJson(int $flags = JSON_UNESCAPED_UNICODE): string
    {
        return json_encode($this->toArray(), $flags | JSON_THROW_ON_ERROR);
    }

    /**
     * 从数组创建实例
     */
    public static function fromArray(array $data): static
    {
        return new static(...$data);
    }
}
