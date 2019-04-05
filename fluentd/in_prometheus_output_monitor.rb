require 'fluent/input'
require 'fluent/plugin/in_monitor_agent'
require 'fluent/plugin/prometheus'

module Fluent::Plugin
  class PrometheusOutputMonitorInput < Fluent::Input
    Fluent::Plugin.register_input('prometheus_output_monitor', self)

    helpers :timer

    config_param :interval, :time, default: 5
    attr_reader :registry

    MONITOR_IVARS = [
      :retry,

      :num_errors,
      :emit_count,

      # for v0.12
      :last_retry_time,

      # from v0.14
      :emit_records,
      :write_count,
      :rollback_count,
    ]

    def initialize
      super
      @registry = ::Prometheus::Client.registry
    end

    def multi_workers_ready?
      true
    end

    def configure(conf)
      super
      hostname = Socket.gethostname
      expander = Fluent::Plugin::Prometheus.placeholder_expander(log)
      placeholders = expander.prepare_placeholders({'hostname' => hostname, 'worker_id' => fluentd_worker_id})
      @base_labels = Fluent::Plugin::Prometheus.parse_labels_elements(conf)
      @base_labels.each do |key, value|
        unless value.is_a?(String)
          raise Fluent::ConfigError, "record accessor syntax is not available in prometheus_output_monitor"
        end
        @base_labels[key] = expander.expand(value, placeholders)
      end

      if defined?(Fluent::Plugin) && defined?(Fluent::Plugin::MonitorAgentInput)
        # from v0.14.6
        @monitor_agent = Fluent::Plugin::MonitorAgentInput.new
      else
        @monitor_agent = Fluent::MonitorAgentInput.new
      end
    end

    def start
      super

      @metrics = {
        buffer_queue_length: @registry.gauge(
          :fluentd_output_status_buffer_queue_length,
          'Current buffer queue length.'),
        buffer_total_queued_size: @registry.gauge(
          :fluentd_output_status_buffer_total_bytes,
          'Current total size of queued buffers.'),
        retry_counts: @registry.counter(
          :fluentd_output_status_retry_count,
          'Current retry counts.'),
        num_errors: @registry.counter(
          :fluentd_output_status_num_errors,
          'Current number of errors.'),
        emit_count: @registry.counter(
          :fluentd_output_status_emit_count,
          'Current emit counts.'),
        emit_records: @registry.counter(
          :fluentd_output_status_emit_records,
          'Current emit records.'),
        write_count: @registry.counter(
          :fluentd_output_status_write_count,
          'Current write counts.'),
        rollback_count: @registry.counter(
          :fluentd_output_status_rollback_count,
          'Current rollback counts.'),
        retry_wait: @registry.gauge(
          :fluentd_output_status_retry_wait,
          'Current retry wait'),
      }
      timer_execute(:in_prometheus_output_monitor, @interval, &method(:update_monitor_info))
    end

    def update_monitor_info
      opts = {
        ivars: MONITOR_IVARS,
        with_retry: true,
      }

      agent_info = @monitor_agent.plugins_info_all(opts).select {|info|
        info['plugin_category'] == 'output'.freeze
      }

      monitor_info = {
        'buffer_queue_length' => @metrics[:buffer_queue_length],
        'buffer_total_queued_size' => @metrics[:buffer_total_queued_size],
        'retry_count' => @metrics[:retry_counts],
      }
      instance_vars_info = {
        num_errors: @metrics[:num_errors],
        write_count: @metrics[:write_count],
        emit_count: @metrics[:emit_count],
        emit_records: @metrics[:emit_records],
        rollback_count: @metrics[:rollback_count],
      }

      agent_info.each do |info|
        label = labels(info)

        monitor_info.each do |name, metric|
          if info[name]
            metric.set(label, info[name])
          end
        end

        if info['instance_variables']
          instance_vars_info.each do |name, metric|
            if info['instance_variables'][name]
              metric.set(label, info['instance_variables'][name])
            end
          end
        end

        # compute current retry_wait
        if info['retry']
          next_time = info['retry']['next_time']
          start_time = info['retry']['start']
          if start_time.nil? && info['instance_variables']
            # v0.12 does not include start, use last_retry_time instead
            start_time = info['instance_variables'][:last_retry_time]
          end

          wait = 0
          if next_time && start_time
            wait = next_time - start_time
          end
          @metrics[:retry_wait].set(label, wait.to_f)
        end
      end
    end

    def labels(plugin_info)
      @base_labels.merge(
        plugin_id: plugin_info["plugin_id"],
        type: plugin_info["type"],
      )
    end
  end
end
