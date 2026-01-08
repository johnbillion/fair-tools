import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import tseslint from 'typescript-eslint';

export default tseslint.config(
	js.configs.recommended,
	...tseslint.configs.recommended,
	prettier,
	{
		languageOptions: {
			globals: {
				console: 'readonly',
				process: 'readonly',
				Buffer: 'readonly',
				URL: 'readonly',
				TextEncoder: 'readonly',
				fetch: 'readonly',
			},
		},
		rules: {
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					caughtErrorsIgnorePattern: '^_',
				},
			],
		},
	},
	{
		ignores: ['node_modules/', 'dist/'],
	},
);
