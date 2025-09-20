<?php

namespace Kode\Jwt\Contract;

interface EventListener
{
    /**
     * 处理事件
     */
    public function handle(object $event): void;
}