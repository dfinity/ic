<script lang="ts">
	/** @type {{ variant: 'filled' | 'outline' | 'soft' }}
	 *  @type {{ color: 'primary' | 'secondary' | 'tertiary' | 'success' | 'warning' | 'error' }}
	 */
	let { variant = 'filled', color = 'primary', children, className = '', ...rest } = $props();
	export { className as class };

	let classes = $derived(
		['badge', `variant-${variant}-${color}`, 'transition-all duration-200', className]
			.filter(Boolean)
			.join(' ')
	);
</script>

<span class={classes} {...rest}>
	<!-- eslint-disable-next-line @typescript-eslint/no-unsafe-call -->
	{@render children?.()}
</span>
