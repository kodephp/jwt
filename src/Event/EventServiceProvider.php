<?php

namespace Kode\Jwt\Event;

class EventServiceProvider
{
    private static ?EventServiceProvider $instance = null;
    private EventDispatcher $dispatcher;
    
    private function __construct()
    {
        $this->dispatcher = EventDispatcher::getInstance();
    }
    
    public static function getInstance(): EventServiceProvider
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        
        return self::$instance;
    }
    
    /**
     * 注册事件监听器
     */
    public function registerListeners(array $listeners): void
    {
        foreach ($listeners as $listener) {
            if (is_callable($listener)) {
                // 匿名函数或可调用数组
                $this->registerListener($listener);
            } elseif (is_string($listener) && class_exists($listener)) {
                // 类名字符串
                $this->registerListenerFromClass($listener);
            } elseif (is_array($listener)) {
                // 数组配置
                $this->registerListenerFromArray($listener);
            }
        }
    }
    
    /**
     * 从可调用项注册监听器
     */
    private function registerListener(callable $listener): void
    {
        // 尝试获取事件类型
        $eventType = $this->getEventTypeFromCallable($listener);
        if ($eventType) {
            $this->dispatcher->addListener($eventType, $listener);
        }
    }
    
    /**
     * 从类名注册监听器
     */
    private function registerListenerFromClass(string $className): void
    {
        $reflection = new \ReflectionClass($className);
        
        // 检查是否实现了EventListener接口
        if ($reflection->hasMethod('handle')) {
            $method = $reflection->getMethod('handle');
            $parameters = $method->getParameters();
            
            if (!empty($parameters)) {
                $paramType = $parameters[0]->getType();
                if ($paramType) {
                    $eventType = $paramType->getName();
                    $parts = explode('\\', $eventType);
                    $eventName = end($parts);
                    
                    $instance = new $className();
                    $this->dispatcher->addListener($eventName, [$instance, 'handle']);
                }
            }
        }
    }
    
    /**
     * 从数组配置注册监听器
     */
    private function registerListenerFromArray(array $config): void
    {
        if (isset($config['event']) && isset($config['listener'])) {
            $event = $config['event'];
            $listener = $config['listener'];
            
            if (is_string($event) && is_callable($listener)) {
                $this->dispatcher->addListener($event, $listener);
            } elseif (is_string($event) && is_string($listener) && class_exists($listener)) {
                $instance = new $listener();
                if (method_exists($instance, 'handle')) {
                    $this->dispatcher->addListener($event, [$instance, 'handle']);
                }
            }
        }
    }
    
    /**
     * 从可调用项获取事件类型
     */
    private function getEventTypeFromCallable(callable $callable): ?string
    {
        if (is_array($callable) && count($callable) === 2) {
            // [$object, 'method'] 或 ['class', 'method']
            $class = is_object($callable[0]) ? get_class($callable[0]) : $callable[0];
            return $this->getEventTypeFromClassMethod($class, $callable[1]);
        } elseif (is_string($callable) && strpos($callable, '::') !== false) {
            // 'Class::method'
            [$class, $method] = explode('::', $callable, 2);
            return $this->getEventTypeFromClassMethod($class, $method);
        } elseif ($callable instanceof \Closure) {
            // 匿名函数
            $reflection = new \ReflectionFunction($callable);
            $parameters = $reflection->getParameters();
            
            if (!empty($parameters)) {
                $paramType = $parameters[0]->getType();
                if ($paramType) {
                    $eventType = $paramType->getName();
                    $parts = explode('\\', $eventType);
                    return end($parts);
                }
            }
        }
        
        return null;
    }
    
    /**
     * 从类方法获取事件类型
     */
    private function getEventTypeFromClassMethod(string $class, string $method): ?string
    {
        if (!class_exists($class)) {
            return null;
        }
        
        $reflection = new \ReflectionClass($class);
        if (!$reflection->hasMethod($method)) {
            return null;
        }
        
        $methodReflection = $reflection->getMethod($method);
        $parameters = $methodReflection->getParameters();
        
        if (!empty($parameters)) {
            $paramType = $parameters[0]->getType();
            if ($paramType) {
                $eventType = $paramType->getName();
                $parts = explode('\\', $eventType);
                return end($parts);
            }
        }
        
        return null;
    }
    
    /**
     * 获取事件调度器
     */
    public function getDispatcher(): EventDispatcher
    {
        return $this->dispatcher;
    }
}