<?php

namespace Kode\Jwt\Contract;

interface EventInterface
{
    /**
     * 获取事件名称
     *
     * @return string
     */
    public function getName(): string;

    /**
     * 获取事件数据
     *
     * @return array<string, mixed>
     */
    public function getData(): array;

    /**
     * 获取事件时间戳
     *
     * @return int
     */
    public function getTimestamp(): int;
}
