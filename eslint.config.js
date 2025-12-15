import js from '@eslint/js';
import prettier from 'eslint-config-prettier';

export default [
	js.configs.recommended,
	prettier,
	{
		languageOptions: {
			globals: {
				console: 'readonly',
				process: 'readonly',
				Buffer: 'readonly',
				URL: 'readonly',
				TextEncoder: 'readonly',
			},
		},
		rules: {
			'no-unused-vars': [
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
		ignores: ['node_modules/'],
	},
];
