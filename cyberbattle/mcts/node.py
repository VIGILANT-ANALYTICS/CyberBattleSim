import copy
import math
import random
import numpy as np
from typing import Any, List, Optional, Tuple

class Node:
    def __init__(self, env, parent, action=None):
        self.env = env
        self.parent = parent
        self.children = []
        self.visits = 0
        self.action = action
        self.accumulated_reward = 0
        self.mean_reward = 0
        self.tried_actions = []
        self.value = 0.0

    def get_valid_untried_action_mask(self):
        valid_actions = self.env.compute_action_mask()
        for action in self.tried_actions:
            for key, val in action.items():
                if key == 'local_vulnerability':
                    valid_actions['local_vulnerability'][tuple(val)] = 0
                if key == 'remote_vulnerability':
                    valid_actions['remote_vulnerability'][tuple(val)] = 0
                if key == 'connect':
                    valid_actions['connect'][tuple(val)] = 0
        return valid_actions

    def is_fully_expanded(self):
        actions = self.get_valid_untried_action_mask()
        return not (actions['local_vulnerability'].any() or actions['remote_vulnerability'].any() or actions['connect'].any())

    def is_terminal(self):
        return self.env.is_done()

    def backpropagate(self, result):
        self.visits += 1
        self.accumulated_reward = self.accumulated_reward + result
        self.mean_reward = self.accumulated_reward / self.visits
        if self.parent:
            self.parent.backpropagate(result)

    def get_all_valid_untried_actions(self):
        mask = self.get_valid_untried_action_mask()
        actions = []

        lv_idx = np.argwhere(mask['local_vulnerability'] == 1)
        for idx in lv_idx:
            actions.append({'local_vulnerability': idx})

        rv_idx = np.argwhere(mask['remote_vulnerability'] == 1)
        for idx in rv_idx:
            actions.append({'remote_vulnerability': idx})

        conn_idx = np.argwhere(mask['connect'] == 1)
        for idx in conn_idx:
            actions.append({'connect': idx})

        return actions

    def expand(self):
        for action in self.get_all_valid_untried_actions():
            new_state = copy.deepcopy(self.env)
            new_state.step(action)
            self.tried_actions.append(action)
            child = Node(new_state, parent=self, action=action)
            self.children.append(child)

    def get_random_untried_action(self):
        untried_action = self.env.sample_valid_action()
        while not self.env.apply_mask(untried_action, self.get_valid_untried_action_mask()):
            untried_action = self.env.sample_valid_action()
        return untried_action

    def eval(self):
        if self.visits == 0:
            return float('inf')
        exploit = self.accumulated_reward / self.visits
        explore = math.sqrt(math.log(self.parent.visits) / self.visits)
        return exploit + explore

    def get_node_probabilities(self):
        temperature = 1.0
        visits = np.array([x.visits for x in self.children])
        if len(visits) == 0:
            return np.array([])
        visits = np.array([x ** (1.0 / temperature) for x in visits])
        probabilities = visits / np.sum(visits)
        probabilities[-1] = max(0, 1 - np.sum(probabilities[0:-1]).item())
        return probabilities
