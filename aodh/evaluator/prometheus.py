#
# Copyright 2017 Mirantis, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime
import json
import operator

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
import requests
import six

from aodh import evaluator
from aodh.evaluator import threshold
from aodh.i18n import _, _LE, _LW


LOG = log.getLogger(__name__)

COMPARATORS = {
    'gt': operator.gt,
    'lt': operator.lt,
    'ge': operator.ge,
    'le': operator.le,
    'eq': operator.eq,
    'ne': operator.ne,
}

OPTS = [
    cfg.StrOpt('url',
               default=None,
               help='URL string for Prometheus API connection')
]


class PrometheusResponseException(Exception):
    """An error from Prometheus response"""
    def __init__(self, type=None, message=None, params=None):
        self.message = message
        self.type = type
        self.params = params

    def __str__(self):
        return _LE("Prometheus request error {type}: {error}. "
                   "Url params: {params}").format(
            error=self.message,
            params=self.params,
            type=self.type
        )


class ServiceNotAvailable(Exception):
    """Unable to communicate with server."""
    def __init__(self, message=None):
        self.message = message

    def __str__(self):
        return self.message or self.__class__.__doc__


class PrometheusEvaluator(threshold.ThresholdEvaluator):

    PROMETHEUS_PATH = "{url}/api/v1/query_range"
    QUERY_FORMAT = ("{statistics_aggregation}"
                    "({per_metric_aggregation}({metric}{labels}[{period}s]))")
    operators = {'ne': '!=', 'gt': '>', 'lt': '<',
                 'le': '<=', 'ge': '>=', 're': '=~', 'eq': '='}

    def __init__(self, conf):
        super(PrometheusEvaluator, self).__init__(conf)
        self.request_url = self.PROMETHEUS_PATH.format(url=conf.prometheus.url)

    @staticmethod
    def _error_reason(transition, error_message):
        if transition:
            return (_('Transition to %(state)s due to error during'
                      'evaluation: %(error)s')
                    % dict(state=evaluator.UNKNOWN, error=error_message))
        return (_('Remaining as %(state)s due to to error during evaluation: '
                  '%(error)s') % dict(state=evaluator.UNKNOWN,
                                      error=error_message))

    @staticmethod
    def _get_compare(op, limit):
        def _compare(point):
            value = float(point[1])
            LOG.debug('Comparing point %(point)s against threshold'
                      ' %(threshold)s. Operator %(op)s',
                      {'point': point, 'threshold': limit, "op": op})
            return op(value, limit)
        return _compare

    @staticmethod
    def _parse_response(content):
        resp = json.loads(content)
        if resp.get("status") == "success":
            result = resp['data']['result']
            if len(result) == 1:
                result = result[0]
                return result.get("values")
            else:
                LOG.warning(_LW("Invalid count of metric response. "
                                "Expected 1 but actual is %s"), len(result))
                return None

        else:
            LOG.warning(_LW("Unexpected status of Prometheus response: %s"),
                        resp.get("status"))
            return None

    @staticmethod
    def _transform_metric(metric):
        return metric.replace(".", "_")

    def _create_label_params(self, queries):
        """Organize labels for the query.

        Labels format is field<op>"value".
        """

        queries = queries or []
        params_list = []
        for query in queries:
            line = '{label}{op}"{value}"'.format(
                label=query["field"],
                op=self.operators.get(query["op"], query["op"]),
                value=query["value"]
            )
            params_list.append(line)
        return "{" + ",".join(params_list) + "}"

    def _make_params(self, aggregation, metric, period, queries, start, end):
        """Create params for the statistics GET request.

        Query format is agr(agr_per_metric(metric{labels}[period])).
        Top aggregation function calculates value from metric aggregations.
        """

        query_line = self.QUERY_FORMAT.format(
            metric=self._transform_metric(metric),
            statistics_aggregation=aggregation,
            per_metric_aggregation="%s_over_time" % aggregation,
            labels=self._create_label_params(queries),
            period=period
        )

        return {"query": query_line, "start": start, "end": end,
                "step": period}

    def _statistics(self, rule, start, end):
        """Return prometheus statistics by time and query"""

        params = self._make_params(rule['statistic'], rule['meter_name'],
                                   rule['period'], rule['query'],
                                   start, end)
        LOG.debug("Make a request with params: %s" % params)
        response = requests.get(self.request_url, params)
        if response.status_code / 200 == 1:
            statistics = self._parse_response(response.content)
            return statistics
        elif response.status_code == 503:
            raise ServiceNotAvailable()
        else:
            error = json.loads(response.content)
            raise PrometheusResponseException(
                type=error.get("errorType"),
                message=error.get("error"),
                params=params)

    def _bound_duration(self, rule):
        """Bound the duration of the statistics query."""
        now = timeutils.utcnow(with_timezone=True)
        # Prometheus uses own parameter to look back onto period ones
        # and we should calculate start only for evaluation_periods > 1
        look_back = max(rule['evaluation_periods'] - 1, 0)
        window = (rule.get('period', None) or rule['granularity']) * look_back
        start = now - datetime.timedelta(seconds=window)
        LOG.debug('query stats from %(start)s to '
                  '%(now)s', {'start': start, 'now': now})

        return start.isoformat(), now.isoformat()

    def _evaluate_rule(self, alarm_rule):
        """Evaluate prometheus rule

        :param alarm_rule - AlarmPrometheusRule

        :returns state - calculated alarm state,
        trending_state
        statistics - Prometheus values from request response
        number_outside - count of alarm satisfied points

        """

        start, end = self._bound_duration(alarm_rule)
        statistics = self._statistics(alarm_rule, start, end) or []
        sufficient = len(statistics) >= alarm_rule['evaluation_periods']

        if not sufficient:
            return evaluator.UNKNOWN, None, statistics, len(statistics)

        op = COMPARATORS[alarm_rule['comparison_operator']]
        limit = alarm_rule['threshold']

        compared = list(six.moves.map(self._get_compare(op, limit),
                                      statistics))
        distilled = all(compared)
        unequivocal = distilled or not any(compared)
        number_outside = len([c for c in compared if c])

        if unequivocal:
            state = evaluator.ALARM if distilled else evaluator.OK
            return state, None, statistics, number_outside
        else:
            trending_state = evaluator.ALARM if compared[-1] else evaluator.OK
            return None, trending_state, statistics, number_outside

    def evaluate(self, alarm):
        if not self.within_time_constraint(alarm):
            LOG.debug('Attempted to evaluate alarm %s, but it is not '
                      'within its time constraint.', alarm.alarm_id)
            return

        try:
            state, trending_state, stats, outside_count = self._evaluate_rule(
                alarm.rule)
            self._transition_alarm(alarm, state, trending_state, stats,
                                   outside_count)
        except PrometheusResponseException as e:
            transition = alarm.state != evaluator.UNKNOWN
            reason = self._error_reason(transition, str(e))
            self._refresh(alarm, evaluator.UNKNOWN, reason, {})
        except Exception:
            raise
