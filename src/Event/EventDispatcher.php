<?php

namespace Kode\Jwt\Event;

use Kode\Jwt\Contract\EventListener;

class EventDispatcher
{
    private static ?EventDispatcher $instance = null;
    private array $listeners = [];

    /**
     * 获取事件调度器单例实例
     *
     * @return self
     */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * 重置实例（主要用于测试）
     */
    public static function resetInstance(): void
    {
        self::$instance = null;
    }

    /**
     * 添加事件监听器
     */
    public function addListener(string $event, EventListener $listener): void
    {
        if (!isset($this->listeners[$event])) {
            $this->listeners[$event] = [];
        }

        $this->listeners[$event][] = $listener;
    }

    /**
     * 移除事件监听器
     */
    public function removeListener(string $event, EventListener $listener): void
    {
        if (!isset($this->listeners[$event])) {
            return;
        }

        $key = array_search($listener, $this->listeners[$event], true);
        if ($key !== false) {
            unset($this->listeners[$event][$key]);
        }
    }

    /**
     * 派发事件
     */
    public function dispatch(object $event): void
    {
        $eventName = get_class($event);

        // 派发具体事件
        if (isset($this->listeners[$eventName])) {
            foreach ($this->listeners[$eventName] as $listener) {
                $listener->handle($event);
            }
        }

        // 派发通用事件监听器
        if (isset($this->listeners['*'])) {
            foreach ($this->listeners['*'] as $listener) {
                $listener->handle($event);
            }
        }
    }

    /**
     * 检查是否有监听器
     */
    public function hasListeners(string $event = null): bool
    {
        if ($event === null) {
            return !empty($this->listeners);
        }

        return isset($this->listeners[$event]) && !empty($this->listeners[$event]);
    }

    /**
     * 获取监听器数量
     */
    public function getListenerCount(string $event = null): int
    {
        if ($event === null) {
            $count = 0;
            foreach ($this->listeners as $listeners) {
                $count += count($listeners);
            }
            return $count;
        }

        return isset($this->listeners[$event]) ? count($this->listeners[$event]) : 0;
    }
}
