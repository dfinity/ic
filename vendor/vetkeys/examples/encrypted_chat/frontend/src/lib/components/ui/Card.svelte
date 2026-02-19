<script lang="ts">
	/** @type {{ variant: 'filled' | 'glass' | 'outlined' }}
	 *  @type {{ padding: 'none' | 'sm' | 'md' | 'lg' }}
	 */
	let { variant = 'filled', padding = 'md', children, className = '', ...rest } = $props();
	export { className as class };

	const variantClasses = {
		filled: 'card',
		glass: 'card variant-glass',
		outlined: 'card variant-outline'
	} as const;

	const paddingClasses = {
		none: '',
		sm: 'p-4',
		md: 'p-6',
		lg: 'p-8'
	} as const;

	let classes = $derived(
		[
			variantClasses[variant as keyof typeof variantClasses],
			paddingClasses[padding as keyof typeof paddingClasses],
			className
		]
			.filter(Boolean)
			.join(' ')
	);
</script>

<div class={classes} {...rest}>
	<!-- eslint-disable-next-line @typescript-eslint/no-unsafe-call -->
	{@render children?.()}
</div>
