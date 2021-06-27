from django.shortcuts import render
import importlib
# Create your views here.


if __name__ == '__main__':
    strategy_tool = importlib.import_module('StrategyTools.redis_unauthorized_20210620171330')
    print(strategy_tool.main('192.168.31.8:6379'))