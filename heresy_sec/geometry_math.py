"""Exact bounded graph mathematics for the HERESY-GEOM profile."""

from __future__ import annotations

from fractions import Fraction
from typing import Iterable

from .errors import HeresySecError


Polynomial = tuple[Fraction, ...]


def _trim(polynomial: Iterable[Fraction]) -> Polynomial:
    values = list(polynomial)
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return tuple(values or [Fraction(0)])


def _degree(polynomial: Polynomial) -> int:
    return len(_trim(polynomial)) - 1


def _monic(polynomial: Polynomial) -> Polynomial:
    value = _trim(polynomial)
    if value == (Fraction(0),):
        return value
    leading = value[-1]
    return _trim(coefficient / leading for coefficient in value)


def _derivative(polynomial: Polynomial) -> Polynomial:
    value = _trim(polynomial)
    if len(value) == 1:
        return (Fraction(0),)
    return _trim(Fraction(index) * value[index] for index in range(1, len(value)))


def _evaluate(polynomial: Polynomial, point: Fraction) -> Fraction:
    result = Fraction(0)
    for coefficient in reversed(_trim(polynomial)):
        result = result * point + coefficient
    return result


def _divide(dividend: Polynomial, divisor: Polynomial) -> tuple[Polynomial, Polynomial]:
    numerator = list(_trim(dividend))
    denominator = _trim(divisor)
    if denominator == (Fraction(0),):
        raise HeresySecError("GEOMETRY_MATH_INVALID", "polynomial division by zero")
    if len(numerator) < len(denominator):
        return (Fraction(0),), tuple(numerator)
    quotient = [Fraction(0)] * (len(numerator) - len(denominator) + 1)
    while len(numerator) >= len(denominator) and any(numerator):
        offset = len(numerator) - len(denominator)
        factor = numerator[-1] / denominator[-1]
        quotient[offset] = factor
        for index, coefficient in enumerate(denominator):
            numerator[offset + index] -= factor * coefficient
        numerator = list(_trim(numerator))
    return _trim(quotient), _trim(numerator)


def _exact_divide(dividend: Polynomial, divisor: Polynomial) -> Polynomial:
    quotient, remainder = _divide(dividend, divisor)
    if remainder != (Fraction(0),):
        raise HeresySecError(
            "GEOMETRY_MATH_INVALID",
            "polynomial factorization was not exact",
        )
    return _trim(quotient)


def _gcd(left: Polynomial, right: Polynomial) -> Polynomial:
    first = _trim(left)
    second = _trim(right)
    while second != (Fraction(0),):
        _, remainder = _divide(first, second)
        first, second = second, remainder
    return _monic(first)


def _square_free_factors(polynomial: Polynomial) -> list[tuple[Polynomial, int]]:
    value = _monic(polynomial)
    if _degree(value) <= 0:
        return []
    repeated = _gcd(value, _derivative(value))
    remaining = _exact_divide(value, repeated)
    multiplicity = 1
    factors: list[tuple[Polynomial, int]] = []
    while _degree(remaining) > 0:
        shared = _gcd(remaining, repeated)
        factor = _exact_divide(remaining, shared)
        if _degree(factor) > 0:
            factors.append((_monic(factor), multiplicity))
        remaining = shared
        repeated = _exact_divide(repeated, shared)
        multiplicity += 1
    return factors


def _sturm_sequence(polynomial: Polynomial) -> list[Polynomial]:
    sequence = [_monic(polynomial), _derivative(_monic(polynomial))]
    while sequence[-1] != (Fraction(0),):
        _, remainder = _divide(sequence[-2], sequence[-1])
        if remainder == (Fraction(0),):
            break
        sequence.append(_trim(-coefficient for coefficient in remainder))
    return sequence


def _variations(sequence: list[Polynomial], point: Fraction) -> int:
    signs: list[int] = []
    for polynomial in sequence:
        value = _evaluate(polynomial, point)
        if value > 0:
            signs.append(1)
        elif value < 0:
            signs.append(-1)
    return sum(1 for left, right in zip(signs, signs[1:]) if left != right)


def _quantized_factor_roots(
    factor: Polynomial,
    *,
    multiplicity: int,
    scale: int,
    upper_bound: int,
) -> list[int]:
    sequence = _sturm_sequence(factor)
    output: list[int] = []
    maximum = upper_bound * scale
    distinct_count = 0
    for quantized in range(maximum + 1):
        left = Fraction(quantized, scale)
        if _evaluate(factor, left) == 0:
            output.extend([quantized] * multiplicity)
            distinct_count += 1
        if quantized == maximum:
            continue
        right = Fraction(quantized + 1, scale)
        interior = _variations(sequence, left) - _variations(sequence, right)
        if _evaluate(factor, right) == 0:
            interior -= 1
        if interior < 0:
            raise HeresySecError(
                "GEOMETRY_SPECTRUM_INVALID",
                "spectral root isolation produced an invalid count",
            )
        output.extend([quantized] * (interior * multiplicity))
        distinct_count += interior
    if distinct_count != _degree(factor):
        raise HeresySecError(
            "GEOMETRY_SPECTRUM_INVALID",
            "spectral roots escaped the deterministic isolation bound",
        )
    return output


def _identity(size: int) -> list[list[int]]:
    return [[1 if row == column else 0 for column in range(size)] for row in range(size)]


def _multiply(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    size = len(left)
    output = [[0] * size for _ in range(size)]
    for row in range(size):
        for pivot in range(size):
            value = left[row][pivot]
            if value == 0:
                continue
            for column in range(size):
                output[row][column] += value * right[pivot][column]
    return output


def characteristic_polynomial(matrix: list[list[int]]) -> list[int]:
    """Return monic characteristic-polynomial coefficients in descending order."""

    size = len(matrix)
    if size == 0 or any(len(row) != size for row in matrix):
        raise HeresySecError(
            "GEOMETRY_SPECTRUM_INVALID",
            "spectral matrix must be a non-empty square integer matrix",
        )
    if any(type(value) is not int for row in matrix for value in row):
        raise HeresySecError(
            "GEOMETRY_SPECTRUM_INVALID",
            "spectral matrix entries must be exact integers",
        )
    auxiliary = _identity(size)
    coefficients = [1]
    for order in range(1, size + 1):
        product = _multiply(matrix, auxiliary)
        trace = sum(product[index][index] for index in range(size))
        if trace % order:
            raise HeresySecError(
                "GEOMETRY_SPECTRUM_INVALID",
                "characteristic-polynomial division was not exact",
            )
        coefficient = -(trace // order)
        coefficients.append(coefficient)
        auxiliary = product
        for index in range(size):
            auxiliary[index][index] += coefficient
    return coefficients


def quantized_real_spectrum(
    matrix: list[list[int]],
    *,
    scale: int,
    upper_bound: int,
) -> tuple[list[int], list[int]]:
    """Return exact characteristic coefficients and floor-quantized real roots."""

    coefficients = characteristic_polynomial(matrix)
    polynomial = tuple(Fraction(value) for value in reversed(coefficients))
    roots: list[int] = []
    for factor, multiplicity in _square_free_factors(polynomial):
        roots.extend(
            _quantized_factor_roots(
                factor,
                multiplicity=multiplicity,
                scale=scale,
                upper_bound=upper_bound,
            )
        )
    roots.sort()
    if len(roots) != len(matrix):
        raise HeresySecError(
            "GEOMETRY_SPECTRUM_INVALID",
            "spectral root multiplicity does not match the matrix dimension",
        )
    return coefficients, roots
